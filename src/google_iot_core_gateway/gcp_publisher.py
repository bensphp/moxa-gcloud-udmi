import datetime
import hashlib
import os
import queue
import random
import socket
import ssl
import threading
import time

import paho.mqtt.client as mqtt

from google_iot_core_gateway.utils.jwt_handler import create_jwt


def _create_paho_client(client_id: str, protocol=mqtt.MQTTv311):
    """Create a Paho MQTT client using CallbackAPIVersion.VERSION1 across Paho 1.x and 2.x."""
    if hasattr(mqtt, "CallbackAPIVersion"):
        return mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION1,
            client_id=client_id,
            protocol=protocol,
        )
    return mqtt.Client(client_id=client_id, protocol=protocol)


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
    ):
        self.logger = logger
        self._connected_devices = dict(connected_devices or {})
        self._attached_proxy_ids = set()
        self._project_id = project_id
        self._cloud_region = cloud_region
        self._registry_id = registry_id
        self._gateway_id = gateway_id
        self._private_key_file = private_key_file
        self._jwt_signing_algorithm = jwt_signing_algorithm
        self._ca_cert = ca_cert
        self._client_cert = client_cert
        self._client_key = client_key
        self._mqtt_bridge_hostname = mqtt_bridge_hostname
        self._mqtt_bridge_port = int(mqtt_bridge_port)
        self._iot_provider = (iot_provider or "gbos").lower()
        self._enable_tls = bool(enable_tls)
        self._mqtt_username = mqtt_username
        self._mqtt_password = mqtt_password

        self._keep_alive_sec = 60
        self._minimum_backoff_time = 1.0
        self._current_backoff_time = 1.0
        # UDMI endpoint.mqtt.mqtt_exponential_backoff requires max backoff >= 120s
        self._maximum_backoff_time = 128.0

        self._protocol_version = mqtt.MQTTv311
        self._is_connected = False
        self._connected_event = threading.Event()
        self._lock = threading.RLock()

        # Downlink queues consumed by gcp_handler
        self.config_queue = config_queue if config_queue is not None else queue.Queue()
        self.error_queue = queue.Queue()

        self.client, self._jwt_exp = self._get_client()

    @property
    def uses_local_mqtt_prefix(self) -> bool:
        return self._iot_provider in ("mqtt", "local")

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

    def _derive_local_mqtt_password(self) -> str:
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

    def error_str(self, rc):
        """Convert a Paho error to a human readable string."""
        return "{}: {}".format(rc, mqtt.error_string(rc))

    def on_connect(self, client, user_data, flags, rc, *args):
        """Callback when the gateway connects to the MQTT broker."""
        if rc != 0:
            self.logger.error(f"MQTT broker refused connection with rc={rc} ({mqtt.connack_string(rc)})")
            self._is_connected = False
            return

        self.logger.info("*************************************************************")
        self.logger.info(
            f"Connected successfully to MQTT bridge {self._mqtt_bridge_hostname}:{self._mqtt_bridge_port}"
        )
        self.logger.info("*************************************************************")

        # Reset exponential backoff on successful connection
        self._current_backoff_time = self._minimum_backoff_time
        self._is_connected = True

        # Subscribe to gateway config, commands, and errors topics BEFORE signaling readiness
        client.subscribe(self._format_device_topic(self._gateway_id, "config"), qos=1)
        client.subscribe(self._format_device_topic(self._gateway_id, "commands/#"), qos=0)
        client.subscribe(self._format_device_topic(self._gateway_id, "errors"), qos=0)

        # Attach and subscribe all configured proxy devices
        self._attach_devices_to_gateway(client=client)
        self._connected_event.set()

    def on_disconnect(self, client, user_data, *args):
        """Paho callback when the gateway disconnects."""
        rc = args[-1] if args else 0
        if rc == 0:
            self.logger.debug(f"on_disconnect: {self.error_str(rc)}")
        else:
            self.logger.error(f"on_disconnect: {self.error_str(rc)}")
        self._is_connected = False
        self._connected_event.clear()

    def on_publish(self, client, user_data, mid, *args):
        self.logger.debug(f"on_publish - mid: {mid}")

    def on_message(self, client, user_data, message):
        """Handle downlink config, command, and gateway error messages."""
        try:
            payload = message.payload.decode("utf-8")
        except UnicodeDecodeError:
            payload = message.payload.decode("latin-1", errors="replace")

        self.logger.debug(
            "Received message on topic '{}' with QoS {} ({} bytes)".format(
                message.topic, message.qos, len(message.payload)
            )
        )

        device_id, subtopic = self._parse_device_topic(message.topic)
        if not device_id or not subtopic:
            return

        if subtopic == "config":
            self.config_queue.put((device_id, payload))
        elif subtopic == "errors":
            self.logger.warning(f"Gateway error received for '{device_id}': {payload}")
            self.error_queue.put((device_id, payload))

    def on_subscribe(self, client, obj, mid, granted_qos, *args):
        self.logger.debug("on_subscribed: " + str(mid) + " " + str(granted_qos))

    def on_log(self, client, user_data, level, buf):
        self.logger.debug("on_log: (%s) - %s ", level, buf)

    def _get_client(self):
        """Create, authenticate, and start the MQTT client loop."""
        client_id = self._get_client_id()
        self.logger.debug(f"Device client_id is '{client_id}'")

        client = _create_paho_client(client_id=client_id, protocol=self._protocol_version)

        jwt_exp = None
        if self.uses_local_mqtt_prefix:
            username = self._mqtt_username if self._mqtt_username is not None else client_id
            password = self._derive_local_mqtt_password()
            if username:
                client.username_pw_set(username=username, password=password)
        else:
            jwt_token, jwt_exp = create_jwt(
                self.logger,
                self._project_id,
                self._private_key_file,
                self._jwt_signing_algorithm,
            )
            client.username_pw_set(username="unused", password=jwt_token)

        if self._enable_tls:
            ca_certs = self._ca_cert if (self._ca_cert and os.path.exists(self._ca_cert)) else None
            certfile = (
                self._client_cert
                if (self._client_cert and os.path.exists(self._client_cert))
                else None
            )
            keyfile = (
                self._client_key
                if (self._client_key and os.path.exists(self._client_key))
                else None
            )
            client.tls_set(
                ca_certs=ca_certs,
                certfile=certfile,
                keyfile=keyfile,
                tls_version=ssl.PROTOCOL_TLSv1_2,
            )

        client.on_connect = self.on_connect
        client.on_disconnect = self.on_disconnect
        client.on_publish = self.on_publish
        client.on_message = self.on_message
        client.on_subscribe = self.on_subscribe
        client.on_log = self.on_log

        self._connected_event.clear()
        self.logger.debug(
            f"Connecting to MQTT bridge {self._mqtt_bridge_hostname}:{self._mqtt_bridge_port}"
        )

        try:
            client.connect(
                host=self._mqtt_bridge_hostname,
                port=self._mqtt_bridge_port,
                keepalive=self._keep_alive_sec,
            )
            client.loop_start()
            self._connected_event.wait(timeout=10.0)
        except socket.timeout:
            self.logger.error("Connection attempt timed out!")
        except (socket.error, OSError) as e:
            self.logger.error(f"Socket error connecting to MQTT bridge: {e}")

        return client, jwt_exp

    def _attach_devices_to_gateway(self, client=None):
        with self._lock:
            target_client = client or self.client
            self._attached_proxy_ids.clear()
            for device_id in list(self._connected_devices.keys()):
                self.attach_device_to_gateway(device_id, client=target_client)
                self.subscribe_to_device_topics(device_id, client=target_client)
                self._attached_proxy_ids.add(device_id)

    def sync_proxy_devices(self, desired_proxy_ids):
        """Dynamically attach newly configured proxy devices and detach removed ones."""
        if desired_proxy_ids is None:
            return
        with self._lock:
            if not self._is_connected:
                return
            desired_set = {
                str(pid) for pid in desired_proxy_ids if str(pid) in self._connected_devices
            }
            to_add = desired_set - self._attached_proxy_ids
            to_remove = self._attached_proxy_ids - desired_set

            for device_id in sorted(to_remove):
                self.detach_device_from_gateway(device_id)
                self.client.unsubscribe(self._format_device_topic(device_id, "config"))
                self._attached_proxy_ids.discard(device_id)

            for device_id in sorted(to_add):
                self.attach_device_to_gateway(device_id)
                self.subscribe_to_device_topics(device_id)
                self._attached_proxy_ids.add(device_id)

    def _reconnect(self):
        self.logger.info("*************************************************************")
        self.logger.info("MQTT Cloud Connection Closed! Reopening with exponential backoff!")
        self.logger.info("*************************************************************")

        delay = self._current_backoff_time + random.uniform(0.0, 1.0)
        self.logger.info(f"Waiting {delay:.2f}s before reconnect attempt")
        time.sleep(delay)

        self._current_backoff_time = min(
            self._current_backoff_time * 2.0, self._maximum_backoff_time
        )

        self.close()
        self.client, self._jwt_exp = self._get_client()

    def _validate_jwt_token(self):
        if self._jwt_exp is None:
            return
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        seconds_till_token_expires = (self._jwt_exp - now_utc).total_seconds()
        if seconds_till_token_expires < 60:
            self.logger.info("*************************************************************")
            self.logger.info("Refreshing JWT token")
            self.logger.info("*************************************************************")
            self.close()
            self.client, self._jwt_exp = self._get_client()

    def is_connection_open(self):
        self._validate_jwt_token()

        if self._is_connected:
            return True

        self._reconnect()
        return self._is_connected

    def subscribe_to_device_topics(self, device_id, client=None):
        target_client = client or self.client
        target_client.subscribe(self._format_device_topic(device_id, "config"), qos=1)
        target_client.subscribe(self._format_device_topic(device_id, "commands/#"), qos=0)

    def publish(self, device_id, payload, topic="state", qos=1):
        device_topic = self._format_device_topic(device_id, topic)
        return self.client.publish(device_topic, payload, qos=qos)

    def attach_device_to_gateway(self, device_id, auth="", client=None):
        target_client = client or self.client
        attach_payload = '{{"authorization" : "{}"}}'.format(auth)
        device_topic = self._format_device_topic(device_id, "attach")
        target_client.publish(device_topic, attach_payload, qos=1)

    def detach_device_from_gateway(self, device_id, client=None):
        target_client = client or self.client
        device_topic = self._format_device_topic(device_id, "detach")
        target_client.publish(device_topic, "{}", qos=1)

    def close(self):
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception as e:
            self.logger.debug(f"Error closing MQTT client: {e}")
        self._is_connected = False
        self._connected_event.clear()
