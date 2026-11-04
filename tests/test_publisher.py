# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""MQTT publisher tests (no broker needed: paho callbacks are driven directly)."""

import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from google_iot_core_gateway.errors import GatewayConfigError
from google_iot_core_gateway.gcp_publisher import GoogleIoTCoreMQTTPublisher, MAX_GATEWAY_ERRORS


class RecordingClient:
    def __init__(self):
        self.calls = []

    def subscribe(self, topic, qos=0):
        self.calls.append(("subscribe", topic))

    def unsubscribe(self, topic):
        self.calls.append(("unsubscribe", topic))

    def publish(self, topic, payload, qos=0):
        self.calls.append(("publish", topic))

    def topics(self, kind):
        return [topic for call, topic in self.calls if call == kind]


def _publisher(logger, tmp_path=None, provider="mqtt", **kwargs):
    defaults = dict(
        logger=logger,
        connected_devices={"EM-11": {}, "EM-12": {}},
        project_id="proj",
        cloud_region="europe-west1",
        registry_id="UK-LON-GLAB",
        gateway_id="CGW-2",
        private_key_file=None,
        ca_cert=None,
        mqtt_bridge_hostname="127.0.0.1",
        mqtt_bridge_port=1,
        iot_provider=provider,
        enable_tls=False,
        autostart=False,
    )
    defaults.update(kwargs)
    return GoogleIoTCoreMQTTPublisher(**defaults)


def _rsa_key(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "rsa_private.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(path)


def test_topic_formats(logger, tmp_path):
    local = _publisher(logger)
    assert local._format_device_topic("EM-11", "state") == "/r/UK-LON-GLAB/d/EM-11/state"
    assert local._parse_device_topic("/r/UK-LON-GLAB/d/EM-11/config") == ("EM-11", "config")
    cloud = _publisher(logger, provider="gbos", private_key_file=_rsa_key(tmp_path))
    assert cloud._format_device_topic("EM-11", "events/pointset") == "/devices/EM-11/events/pointset"
    assert cloud._get_client_id() == "projects/proj/locations/europe-west1/registries/UK-LON-GLAB/devices/CGW-2"


def test_explicit_ca_must_exist(logger, tmp_path):
    with pytest.raises(GatewayConfigError):
        _publisher(logger, enable_tls=True, ca_cert=str(tmp_path / "missing.crt"), ca_cert_required=True)


def test_default_ca_bundle_missing_falls_back_to_system_store(logger, tmp_path):
    publisher = _publisher(logger, enable_tls=True, ca_cert=str(tmp_path / "roots.pem"), ca_cert_required=False)
    assert publisher.client is not None


def test_missing_client_certificate_is_fatal(logger, tmp_path):
    with pytest.raises(GatewayConfigError):
        _publisher(logger, enable_tls=True, client_cert=str(tmp_path / "client.crt"))


def test_on_connect_attaches_only_desired_proxies_and_counts_sessions(logger):
    publisher = _publisher(logger)
    publisher.sync_proxy_devices(["EM-12", "NOT-CONFIGURED"])  # while disconnected
    client = RecordingClient()
    publisher.on_connect(client, None, {}, 0)
    assert publisher.is_connected()
    assert publisher.connection_generation == 1
    assert client.topics("publish") == ["/r/UK-LON-GLAB/d/EM-12/attach"]
    assert "/r/UK-LON-GLAB/d/CGW-2/config" in client.topics("subscribe")
    assert "/r/UK-LON-GLAB/d/CGW-2/errors" in client.topics("subscribe")

    publisher.on_disconnect(client, None, 1)
    assert not publisher.is_connected()
    publisher.on_connect(client, None, {}, 0)
    assert publisher.connection_generation == 2


def test_refused_connection_is_not_connected(logger):
    publisher = _publisher(logger)
    publisher.on_connect(RecordingClient(), None, {}, 5)
    assert not publisher.is_connected()
    assert publisher.connection_generation == 0


def test_gateway_error_messages_are_bounded(logger):
    publisher = _publisher(logger)

    class Msg:
        def __init__(self, topic, payload):
            self.topic = topic
            self.payload = payload
            self.qos = 0

    for i in range(MAX_GATEWAY_ERRORS * 5):
        publisher.on_message(None, None, Msg("/r/UK-LON-GLAB/d/CGW-2/errors", f'{{"n": {i}}}'.encode()))
    drained = publisher.drain_gateway_errors()
    assert len(drained) == MAX_GATEWAY_ERRORS
    assert drained[-1] == ("CGW-2", '{"n": %d}' % (MAX_GATEWAY_ERRORS * 5 - 1))
    assert publisher.drain_gateway_errors() == []


def test_config_messages_are_queued(logger):
    publisher = _publisher(logger)

    class Msg:
        topic = "/r/UK-LON-GLAB/d/EM-11/config"
        payload = b'{"timestamp": "x"}'
        qos = 1

    publisher.on_message(None, None, Msg())
    assert publisher.config_queue.get_nowait() == ("EM-11", '{"timestamp": "x"}')


def test_jwt_refresh_reconnects_the_same_client(logger, tmp_path):
    publisher = _publisher(logger, tmp_path, provider="gbos", private_key_file=_rsa_key(tmp_path))
    original_client = publisher.client
    calls = []
    for name in ("disconnect", "loop_stop", "loop_start"):
        setattr(original_client, name, lambda *a, _n=name, **k: calls.append(_n))
    original_client.connect_async = lambda *a, **k: calls.append("connect_async")

    publisher.maintain()  # token still fresh: nothing happens
    assert calls == []

    publisher._jwt_exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=30)
    publisher._connected.set()
    publisher.maintain()
    assert calls == ["disconnect", "loop_stop", "connect_async", "loop_start"]
    assert publisher.client is original_client  # queued QoS 1 messages are kept
    assert publisher._jwt_seconds_left() > 3000
