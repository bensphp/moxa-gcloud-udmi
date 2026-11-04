# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""MQTT client for ClearBlade / Cloud IoT Core style brokers and local UDMI MQTT brokers.

One paho client is used for the lifetime of the process. Reconnection is handled by paho's own
exponential backoff (1 s .. 120 s, UDMI `mqtt_client.md`), so unacknowledged QoS 1 messages stay
queued in the client and are re-sent after a reconnect. JWT refreshes reconnect the same client.
"""

import collections
import datetime
import hashlib
import logging
import os
import queue
import ssl
import threading
import time

import paho.mqtt.client as mqtt

from google_iot_core_gateway.errors import GatewayConfigError
from google_iot_core_gateway.utils.jwt_handler import DEFAULT_JWT_EXPIRES_MINUTES, create_jwt

KEEPALIVE_SEC = 60
RECONNECT_MIN_DELAY_SEC = 1
RECONNECT_MAX_DELAY_SEC = 120  # UDMI mqtt_client.md: at most 120 s between connection attempts
MAX_QUEUED_MESSAGES = 1000  # bounds memory while the cloud link is down
MAX_GATEWAY_ERRORS = 200
JWT_REFRESH_MARGIN_SEC = 300
LOG_THROTTLE_SEC = 300.0


def _create_paho_client(client_id: str, protocol=mqtt.MQTTv311):
    """Create a Paho MQTT client using CallbackAPIVersion.VERSION1 across Paho 1.x and 2.x."""
    if hasattr(mqtt, "CallbackAPIVersion"):
        return mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION1,
            client_id=client_id,
            protocol=protocol,
        )
    return mqtt.Client(client_id=client_id, protocol=protocol)


def _rc_value(rc) -> int:
    """Normalize paho return/reason codes (int in 1.x, ReasonCode objects in 2.x)."""
    try:
        return int(getattr(rc, "value", rc))
    except (TypeError, ValueError):
        return -1


class GoogleIoTCoreMQTTPublisher:

    def __init__(
        self,
        logger,
        connected_devices,
        project_id,
        cloud_region,
        registry_id,
        gateway_id,
        private_key_file,
        ca_cert,
        mqtt_bridge_hostname,
        mqtt_bridge_port,
        jwt_signing_algorithm="RS256",
        iot_provider="gbos",
        enable_tls=True,
        client_cert=None,
        client_key=None,
        mqtt_username=None,
        mqtt_password=None,
        config_queue=None,
        jwt_expires_minutes=DEFAULT_JWT_EXPIRES_MINUTES,
        ca_cert_required=True,
        autostart=True,
    ):
        self.logger = logger
        self._connected_devices = dict(connected_devices or {})
        self._desired_proxy_ids = set(self._connected_devices)
        self._attached_proxy_ids = set()
        self._project_id = project_id
        self._cloud_region = cloud_region
        self._registry_id = registry_id
        self._gateway_id = gateway_id
        self._private_key_file = private_key_file
        self._jwt_signing_algorithm = jwt_signing_algorithm
        self._jwt_expires_minutes = int(jwt_expires_minutes)
        self._ca_cert = ca_cert
        self._ca_cert_required = bool(ca_cert_required)
        self._client_cert = client_cert
        self._client_key = client_key
        self._mqtt_bridge_hostname = mqtt_bridge_hostname
        self._mqtt_bridge_port = int(mqtt_bridge_port)
        self._iot_provider = (iot_provider or "gbos").lower()
        self._enable_tls = bool(enable_tls)
        self._mqtt_username = mqtt_username
        self._mqtt_password = mqtt_password

        self._lock = threading.RLock()
        self._connected = threading.Event()
        self._connection_generation = 0
        self._started = False
        self._jwt_exp = None
        self._log_throttle = {}

        # Downlink queues consumed by gcp_handler (config is never dropped; errors are bounded).
        self.config_queue = config_queue if config_queue is not None else queue.Queue()
        self._gateway_errors = collections.deque(maxlen=MAX_GATEWAY_ERRORS)

        self.client = self._create_client()
        if autostart:
            self.start()

    # ---------------------------------------------------------------- topics

    @property
    def uses_local_mqtt_prefix(self) -> bool:
        return self._iot_provider in ("mqtt", "local")

    @property
    def connection_generation(self) -> int:
        """Incremented on every successful (re)connect."""
        return self._connection_generation

    def is_connected(self) -> bool:
        return self._connected.is_set()

    def wait_for_connection(self, timeout: float) -> bool:
        return self._connected.wait(timeout)

    def _get_client_id(self) -> str:
        if self.uses_local_mqtt_prefix:
            return f"/r/{self._registry_id}/d/{self._gateway_id}"
        return (
            f"projects/{self._project_id}/locations/{self._cloud_region}"
            f"/registries/{self._registry_id}/devices/{self._gateway_id}"
        )

    def _format_device_topic(self, device_id: str, subtopic: str) -> str:
        if self.uses_local_mqtt_prefix:
            return f"/r/{self._registry_id}/d/{device_id}/{subtopic}"
        return f"/devices/{device_id}/{subtopic}"

    def _parse_device_topic(self, topic: str):
        """Parse incoming MQTT topic into (device_id, subtopic) or (None, None)."""
        if self.uses_local_mqtt_prefix:
            prefix = f"/r/{self._registry_id}/d/"
            if topic.startswith(prefix):
                rest = topic[len(prefix):]
                parts = rest.split("/", 1)
                if len(parts) == 2:
                    return parts[0], parts[1]
        if topic.startswith("/devices/"):
            rest = topic[len("/devices/"):]
            parts = rest.split("/", 1)
            if len(parts) == 2:
                return parts[0], parts[1]
        return None, None

    # ------------------------------------------------------------ credentials

    def _derive_local_mqtt_password(self) -> str:
        """UDMI local broker convention: first 8 hex chars of sha256(private pkcs8 key)."""
        if self._mqtt_password is not None:
            return self._mqtt_password
        if not self._private_key_file:
            return ""
        key_dir = os.path.dirname(self._private_key_file)
        for candidate in ("rsa_private.pkcs8", "ec_private.pkcs8"):
            cand_path = os.path.join(key_dir, candidate)
            if os.path.exists(cand_path):
                with open(cand_path, "rb") as fh:
                    return hashlib.sha256(fh.read()).hexdigest()[:8]
        if os.path.exists(self._private_key_file):
            with open(self._private_key_file, "rb") as fh:
                return hashlib.sha256(fh.read()).hexdigest()[:8]
        return ""

    def _refresh_jwt_credentials(self):
        jwt_token, jwt_exp = create_jwt(
            self.logger,
            self._project_id,
            self._private_key_file,
            self._jwt_signing_algorithm,
            expires_minutes=self._jwt_expires_minutes,
        )
        self.client.username_pw_set(username="unused", password=jwt_token)
        self._jwt_exp = jwt_exp

    def _jwt_seconds_left(self):
        if self._jwt_exp is None:
            return None
        return (self._jwt_exp - datetime.datetime.now(datetime.timezone.utc)).total_seconds()

    def _build_tls_context(self) -> ssl.SSLContext:
        ca_certs = None
        if self._ca_cert:
            if os.path.exists(self._ca_cert):
                ca_certs = self._ca_cert
            elif self._ca_cert_required:
                raise GatewayConfigError(f"CA certificate file '{self._ca_cert}' not found")
            else:
                self.logger.warning(
                    f"Default CA bundle '{self._ca_cert}' not found; using the system trust store"
                )
        for label, path in (("client certificate", self._client_cert), ("client key", self._client_key)):
            if path and not os.path.exists(path):
                raise GatewayConfigError(f"Configured {label} file '{path}' not found")

        context = ssl.create_default_context(cafile=ca_certs)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self._client_cert:
            context.load_cert_chain(self._client_cert, self._client_key or None)
        return context

    def _create_client(self):
        client_id = self._get_client_id()
        self.logger.debug(f"Device client_id is '{client_id}'")
        client = _create_paho_client(client_id=client_id)
        self.client = client

        if self.uses_local_mqtt_prefix:
            username = self._mqtt_username if self._mqtt_username is not None else client_id
            if username:
                client.username_pw_set(username=username, password=self._derive_local_mqtt_password())
        else:
            self._refresh_jwt_credentials()

        if self._enable_tls:
            client.tls_set_context(self._build_tls_context())

        client.reconnect_delay_set(min_delay=RECONNECT_MIN_DELAY_SEC, max_delay=RECONNECT_MAX_DELAY_SEC)
        client.max_queued_messages_set(MAX_QUEUED_MESSAGES)
        client.on_connect = self.on_connect
        client.on_disconnect = self.on_disconnect
        client.on_publish = self.on_publish
        client.on_message = self.on_message
        client.on_subscribe = self.on_subscribe
        if self.logger.isEnabledFor(logging.DEBUG):
            client.on_log = self.on_log
        return client

    # ---------------------------------------------------------------- lifecycle

    def start(self):
        """Start connecting in the background; paho retries with exponential backoff."""
        if self._started:
            return
        self._started = True
        self.logger.info(
            f"Connecting to MQTT bridge {self._mqtt_bridge_hostname}:{self._mqtt_bridge_port}"
        )
        self.client.connect_async(
            host=self._mqtt_bridge_hostname,
            port=self._mqtt_bridge_port,
            keepalive=KEEPALIVE_SEC,
        )
        self.client.loop_start()

    def maintain(self):
        """Called periodically from the main loop: refresh the JWT before it expires."""
        seconds_left = self._jwt_seconds_left()
        if seconds_left is None or seconds_left > JWT_REFRESH_MARGIN_SEC:
            return
        try:
            self._refresh_jwt_credentials()
        except Exception as exc:  # noqa: BLE001 - retry on the next maintenance pass
            self._log_throttled(("jwt",), self.logger.error, f"Could not create a new JWT: {exc}")
            return
        if not self.is_connected():
            return  # the next automatic reconnect attempt uses the new token
        self.logger.info("Refreshing JWT: reconnecting the MQTT session with a new token")
        with self._lock:
            self.client.disconnect()
            self.client.loop_stop()
            self.client.connect_async(
                host=self._mqtt_bridge_hostname,
                port=self._mqtt_bridge_port,
                keepalive=KEEPALIVE_SEC,
            )
            self.client.loop_start()

    def close(self, timeout: float = 5.0):
        """Disconnect and stop the network thread without blocking shutdown for long."""
        try:
            self.client.disconnect()
        except Exception as exc:  # noqa: BLE001 - best effort during shutdown
            self.logger.debug(f"Error disconnecting MQTT client: {exc}")
        stopper = threading.Thread(target=self._safe_loop_stop, daemon=True)
        stopper.start()
        stopper.join(timeout)
        self._connected.clear()

    def _safe_loop_stop(self):
        try:
            self.client.loop_stop()
        except Exception:  # noqa: BLE001 - best effort during shutdown
            pass

    # ---------------------------------------------------------------- callbacks

    def _log_throttled(self, key, level_fn, message):
        now = time.monotonic()
        last = self._log_throttle.get(key)
        if last is None or now - last >= LOG_THROTTLE_SEC:
            self._log_throttle[key] = now
            level_fn(message)

    def error_str(self, rc):
        """Convert a Paho error to a human readable string."""
        return "{}: {}".format(rc, mqtt.error_string(_rc_value(rc)))

    def on_connect(self, client, user_data, flags, rc, *args):
        rc_val = _rc_value(rc)
        if rc_val != 0:
            self._connected.clear()
            self._log_throttled(
                ("connack", rc_val),
                self.logger.error,
                f"MQTT broker refused connection: {mqtt.connack_string(rc_val)} (rc={rc_val})",
            )
            if not self.uses_local_mqtt_prefix and rc_val in (4, 5):
                try:
                    self._refresh_jwt_credentials()
                except Exception as exc:  # noqa: BLE001 - keep the network thread alive
                    self.logger.error(f"Could not create a new JWT: {exc}")
            return

        self.logger.info(
            f"Connected to MQTT bridge {self._mqtt_bridge_hostname}:{self._mqtt_bridge_port}"
        )
        client.subscribe(self._format_device_topic(self._gateway_id, "config"), qos=1)
        client.subscribe(self._format_device_topic(self._gateway_id, "commands/#"), qos=0)
        client.subscribe(self._format_device_topic(self._gateway_id, "errors"), qos=0)
        with self._lock:
            self._attached_proxy_ids.clear()
            for device_id in sorted(self._desired_proxy_ids):
                self.attach_device_to_gateway(device_id, client=client)
                self.subscribe_to_device_topics(device_id, client=client)
                self._attached_proxy_ids.add(device_id)
            self._connection_generation += 1
        self._connected.set()

    def on_disconnect(self, client, user_data, *args):
        rc = args[-1] if args else 0
        self._connected.clear()
        if _rc_value(rc) != 0:
            self._log_throttled(
                ("disconnect", _rc_value(rc)),
                self.logger.warning,
                f"MQTT connection lost ({self.error_str(rc)}); reconnecting with backoff",
            )
        seconds_left = self._jwt_seconds_left()
        if seconds_left is not None and seconds_left <= JWT_REFRESH_MARGIN_SEC:
            try:
                self._refresh_jwt_credentials()
            except Exception as exc:  # noqa: BLE001 - keep the network thread alive
                self.logger.error(f"Could not create a new JWT: {exc}")

    def on_publish(self, client, user_data, mid, *args):
        self.logger.debug(f"on_publish - mid: {mid}")

    def on_message(self, client, user_data, message):
        """Queue downlink config and gateway error messages for the main loop."""
        try:
            payload = message.payload.decode("utf-8")
        except UnicodeDecodeError:
            payload = message.payload.decode("latin-1", errors="replace")

        device_id, subtopic = self._parse_device_topic(message.topic)
        if not device_id or not subtopic:
            return
        if subtopic == "config":
            self.config_queue.put((device_id, payload))
        elif subtopic == "errors":
            self._gateway_errors.append((device_id, payload))

    def drain_gateway_errors(self) -> list:
        drained = []
        while True:
            try:
                drained.append(self._gateway_errors.popleft())
            except IndexError:
                return drained

    def on_subscribe(self, client, obj, mid, granted_qos, *args):
        self.logger.debug("on_subscribed: " + str(mid) + " " + str(granted_qos))

    def on_log(self, client, user_data, level, buf):
        self.logger.debug("on_log: (%s) - %s ", level, buf)

    # ------------------------------------------------------------ gateway ops

    def sync_proxy_devices(self, desired_proxy_ids):
        """Attach newly configured proxy devices and detach removed ones (now or on connect)."""
        if desired_proxy_ids is None:
            return
        with self._lock:
            desired_set = {
                str(pid) for pid in desired_proxy_ids if str(pid) in self._connected_devices
            }
            self._desired_proxy_ids = desired_set
            if not self.is_connected():
                return
            for device_id in sorted(self._attached_proxy_ids - desired_set):
                self.detach_device_from_gateway(device_id)
                self.client.unsubscribe(self._format_device_topic(device_id, "config"))
                self.client.unsubscribe(self._format_device_topic(device_id, "commands/#"))
                self._attached_proxy_ids.discard(device_id)
            for device_id in sorted(desired_set - self._attached_proxy_ids):
                self.attach_device_to_gateway(device_id)
                self.subscribe_to_device_topics(device_id)
                self._attached_proxy_ids.add(device_id)

    def subscribe_to_device_topics(self, device_id, client=None):
        target_client = client or self.client
        target_client.subscribe(self._format_device_topic(device_id, "config"), qos=1)
        target_client.subscribe(self._format_device_topic(device_id, "commands/#"), qos=0)

    def publish(self, device_id, payload, topic="state", qos=1):
        """Publish and return paho's MQTTMessageInfo (`.rc == MQTT_ERR_SUCCESS` if queued)."""
        device_topic = self._format_device_topic(device_id, topic)
        return self.client.publish(device_topic, payload, qos=qos)

    def attach_device_to_gateway(self, device_id, auth="", client=None):
        target_client = client or self.client
        attach_payload = '{{"authorization" : "{}"}}'.format(auth)
        target_client.publish(self._format_device_topic(device_id, "attach"), attach_payload, qos=1)

    def detach_device_from_gateway(self, device_id, client=None):
        target_client = client or self.client
        target_client.publish(self._format_device_topic(device_id, "detach"), "{}", qos=1)
