import logging
import queue
import threading
import time

import paho.mqtt.client as mqtt


def _create_paho_client(client_id="", protocol=mqtt.MQTTv311):
    """Create a Paho MQTT client using CallbackAPIVersion.VERSION1 across Paho 1.x and 2.x."""
    if hasattr(mqtt, "CallbackAPIVersion"):
        return mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION1,
            client_id=client_id,
            protocol=protocol,
        )
    return mqtt.Client(client_id=client_id, protocol=protocol)


class MosquittoMQTTSubscriber:

    def __init__(
        self,
        logger,
        google_iot_core_queue,
        host="127.0.0.1",
        port=1883,
        ca_certs=None,
        certfile=None,
        keyfile=None,
        disable_tls_cert_verification=False,
        enable_tls=False,
        topic="MXcloudgate",
    ):
        self.logger = logger
        self.google_iot_core_queue = google_iot_core_queue

        self._broker_url = host
        self._port = int(port)
        self._trusted_root_ca = ca_certs
        self._x509_certificate = certfile
        self._private_key = keyfile
        self._tls_insecure_set = disable_tls_cert_verification
        self._enable_tls = enable_tls
        self._topic = topic
        self._dropped = 0
        self._last_drop_log = 0.0

        self.client = _create_paho_client()
        self.client.reconnect_delay_set(min_delay=1, max_delay=60)

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_publish = self._on_publish
        self.client.on_subscribe = self._on_subscribe
        self.client.on_message = self._on_message
        if self.logger.isEnabledFor(logging.DEBUG):
            self.client.on_log = self._on_log

        if self._enable_tls:
            # paho picks PROTOCOL_TLS_CLIENT (TLS 1.2+, certificate verification on).
            self.client.tls_set(
                ca_certs=self._trusted_root_ca,
                certfile=self._x509_certificate,
                keyfile=self._private_key,
            )
            self.client.tls_insecure_set(self._tls_insecure_set)

        try:
            self.client.connect_async(self._broker_url, self._port, 60)
        except Exception as e:
            logger.error("Error preparing internal broker connection: {}".format(e))

    def _error_str(self, rc):
        """Convert a Paho error to a human readable string."""
        return "{}: {}".format(rc, mqtt.error_string(rc))

    def _on_connect(self, client, user_data, flags, rc, *args):
        self.logger.debug(f"on_connect: {mqtt.connack_string(rc)}")
        if rc == 0:
            self.logger.info(
                "Connected successfully to MXcloudgate internal broker: {}:{}".format(
                    self._broker_url, self._port
                )
            )
            self.logger.info(f"Subscribing to internal broker topic '{self._topic}'")
            client.subscribe(self._topic, 0)
        else:
            self.logger.error(f"Internal broker connection failed with rc={rc}")

    def _on_disconnect(self, client, user_data, *args):
        rc = args[-1] if args else 0
        self.logger.debug(f"Internal broker on_disconnect: {self._error_str(rc)}")

    def _on_publish(self, client, user_data, mid, *args):
        self.logger.debug(f"on_publish: {mid}")

    def _on_subscribe(self, client, user_data, mid, granted_qos, *args):
        self.logger.debug("on_subscribed: " + str(mid) + " " + str(granted_qos))

    def _on_message(self, client, user_data, message):
        try:
            payload = message.payload.decode("utf-8")
        except UnicodeDecodeError:
            self.logger.warning("Ignoring non-UTF8 payload on internal broker")
            return

        self.logger.debug("Received message on internal topic '%s' with QoS %s", message.topic, message.qos)

        # Non-blocking enqueue: drop the oldest frame if the queue is full so the MQTT loop never
        # blocks; report drops (rate-limited) because they mean the main loop is falling behind.
        try:
            self.google_iot_core_queue.put_nowait(payload)
            return
        except queue.Full:
            pass
        try:
            self.google_iot_core_queue.get_nowait()
        except queue.Empty:
            pass
        try:
            self.google_iot_core_queue.put_nowait(payload)
        except queue.Full:
            pass
        self._dropped += 1
        now = time.monotonic()
        if now - self._last_drop_log >= 300.0:
            self.logger.warning(
                f"Internal Modbus frame queue full: dropped {self._dropped} oldest frame(s) so far"
            )
            self._last_drop_log = now

    def _on_log(self, client, user_data, level, buf):
        self.logger.debug("on_log: (%s) - %s ", level, buf)

    def run(self):
        self.client.loop_start()

    def stop(self, timeout: float = 5.0):
        """Disconnect, then stop the network thread without blocking shutdown for long."""
        try:
            self.client.disconnect()
        except Exception as e:  # noqa: BLE001 - best effort during shutdown
            self.logger.debug(f"Error disconnecting internal broker subscriber: {e}")
        stopper = threading.Thread(target=self._safe_loop_stop, daemon=True)
        stopper.start()
        stopper.join(timeout)

    def _safe_loop_stop(self):
        try:
            self.client.loop_stop()
        except Exception:  # noqa: BLE001 - best effort during shutdown
            pass


def main():
    logger = logging.getLogger(__name__)
    messages_queue = queue.Queue(maxsize=500)

    int_broker_subscriber = MosquittoMQTTSubscriber(logger, messages_queue)
    int_broker_subscriber.run()


if __name__ == "__main__":
    main()
