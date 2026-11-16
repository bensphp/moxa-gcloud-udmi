# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Security, configuration, routing and main-loop wiring tests."""

import datetime
import json
import logging
import queue
import ssl
import threading
import types

import jwt
import pytest

import mxcloudgate_simulator as sim
from conftest import RESOURCES_DIR, write_site_model
from google_iot_core_gateway import gcp_handler
from google_iot_core_gateway.errors import GatewayConfigError
from google_iot_core_gateway.gcp_handler import process_payloads
from google_iot_core_gateway.udmi_handler import udmi_handler as module
from google_iot_core_gateway.utils.config_handler import ConfigHandler, redact_secrets
from google_iot_core_gateway.utils.jwt_handler import create_jwt
from helpers import RecordingClient, make_publisher, write_rsa_key


def test_jwt_claims_and_lifetime(logger, tmp_path):
    publisher = make_publisher(logger, provider="iot_core", private_key_file=write_rsa_key(tmp_path),
                           jwt_expires_minutes=60)
    token = publisher.client._password.decode() if isinstance(publisher.client._password, bytes) else publisher.client._password
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == "proj"
    assert claims["exp"] - claims["iat"] == 3600


def test_short_jwt_lifetimes_do_not_cause_a_refresh_storm(logger, tmp_path):
    # 5-minute tokens (now rejected by config validation) used to storm: margin 300 s >= lifetime.
    publisher = make_publisher(logger, provider="iot_core", private_key_file=write_rsa_key(tmp_path),
                               jwt_expires_minutes=5)
    calls = []
    original = publisher._refresh_jwt_credentials

    def counting_refresh():
        calls.append(1)
        original()

    publisher._refresh_jwt_credentials = counting_refresh
    for _ in range(100):
        publisher.maintain()
    assert calls == []  # a fresh token is not refreshed again and again
    publisher._jwt_exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=30)
    for _ in range(100):
        publisher.maintain()
    assert len(calls) == 1  # exactly one refresh once inside the refresh window


@pytest.mark.parametrize("minutes,ok", [(5, False), (9, False), (10, True), (1440, True), (1441, False)])
def test_jwt_lifetime_is_validated(tmp_path, minutes, ok):
    site = write_site_model(tmp_path)
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({
        "google_cloud": {"jwt_expires_minutes": minutes},
        "site_details": {"gateway_id": "CGW-1", "proxy_ids": {"EM-1": {"type": "PM5561", "modbus_slave_id": 1}}},
        "environment_setup": {"udmi_site_model_path": str(site), "resources_path": RESOURCES_DIR,
                              "state_dir": str(tmp_path / "state")},
    }))
    load = lambda: ConfigHandler(logging.getLogger("jwt"), types.SimpleNamespace(config_file=str(cfg)))  # noqa: E731
    if ok:
        assert load().google_cloud__jwt_expires_minutes == minutes
    else:
        with pytest.raises(GatewayConfigError, match="jwt_expires_minutes"):
            load()


@pytest.mark.parametrize("requested,lifetime_sec", [(0, 60), (10**6, 1440 * 60)])
def test_jwt_handler_clamps_the_lifetime(logger, tmp_path, requested, lifetime_sec):
    """Defence in depth behind the config validation: a token never outlives the 24 h maximum."""
    token, _expiry = create_jwt(logger, "proj", write_rsa_key(tmp_path), "RS256", expires_minutes=requested)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == lifetime_sec


def test_tls_context_requires_verified_tls_1_2_or_newer(logger):
    context = make_publisher(logger, enable_tls=True)._build_tls_context()
    assert context.minimum_version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_secrets_are_redacted_from_config_logs(tmp_path, caplog):
    site = write_site_model(tmp_path)
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({
        "google_cloud": {"iot_provider": "mqtt", "mqtt_password": "s3cr3t-value"},
        "site_details": {"gateway_id": "CGW-1", "proxy_ids": {"EM-1": {"type": "PM5561", "modbus_slave_id": 1}}},
        "environment_setup": {"udmi_site_model_path": str(site), "resources_path": RESOURCES_DIR,
                              "state_dir": str(tmp_path / "state")},
    }))
    log = logging.getLogger("redaction-test")
    log.setLevel(logging.DEBUG)
    with caplog.at_level(logging.DEBUG, logger="redaction-test"):
        config = ConfigHandler(log, types.SimpleNamespace(config_file=str(cfg)))
    assert config.google_cloud__mqtt_password == "s3cr3t-value"
    assert "s3cr3t-value" not in caplog.text
    assert redact_secrets({"a": {"mqtt_password": "x"}}) == {"a": {"mqtt_password": "***"}}


def test_duplicate_slave_ids_are_rejected(tmp_path):
    site = write_site_model(tmp_path)
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({
        "site_details": {"gateway_id": "CGW-1", "proxy_ids": {
            "EM-1": {"type": "PM5561", "modbus_slave_id": 1},
            "EM-2": {"type": "PM5111", "modbus_slave_id": 1}}},
        "environment_setup": {"udmi_site_model_path": str(site), "resources_path": RESOURCES_DIR},
    }))
    with pytest.raises(GatewayConfigError, match="modbus_slave_id 1"):
        ConfigHandler(logging.getLogger("dup"), types.SimpleNamespace(config_file=str(cfg)))


def test_frames_are_routed_to_the_right_meter(tmp_path, logger, monkeypatch):
    monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
    site = write_site_model(tmp_path, with_second_meter=True)
    h = module.UDMIHandler(logger, RESOURCES_DIR, str(site), config_wait_timeout_sec=0)
    h.add_device_to_dict(1, "EM-1", "PM5561", port="ttyM0")
    h.add_device_to_dict(2, "EM-2", "PM5111", port="ttyM0")
    q = queue.Queue()
    for slave in (1, 2):
        for req, resp in sim.build_slave_frames(slave, 1):
            q.put(json.dumps({"rtu_request": req.hex(), "rtu_response": resp.hex()}))
    process_payloads(logger, q, h)
    assert json.loads(h.get_state_payload("EM-1"))["system"]["serial_no"] == "52110001"
    assert json.loads(h.get_state_payload("EM-2"))["system"]["serial_no"] == "51110002"
    assert json.loads(h.get_state_payload("EM-2"))["system"]["hardware"]["model"] == "PM5111"


@pytest.mark.parametrize("mode,expected", [("strict", True), ("off", False)])
def test_crc_check_setting_reaches_the_decoder(monkeypatch, logger, mode, expected):
    seen = []
    stop = threading.Event()

    def fake_process(_logger, _queue, _handler, strict_crc=True, **_kw):
        seen.append(strict_crc)
        stop.set()
        return 0

    monkeypatch.setattr(gcp_handler, "process_payloads", fake_process)

    class Pub:
        connection_generation = 0
        config_queue = queue.Queue()

        def drain_gateway_errors(self):
            return []

        def maintain(self):
            pass

        def is_connected(self):
            return False

    class Handler:
        restart_requested = False

        def tick(self):
            pass

    gcp_handler.run_gateway_loop(logger, types.SimpleNamespace(modbus__crc_check=mode), Pub(), Handler(), queue.Queue(), stop)
    assert seen == [expected]


def test_removed_proxies_are_detached(logger):
    publisher = make_publisher(logger)
    client = RecordingClient()
    publisher.on_connect(client, None, {}, 0)
    publisher.client = client
    publisher.sync_proxy_devices(["EM-1"])
    assert "/r/ZZ-TRI-FECTA/d/EM-2/detach" in client.topics("publish")
    assert "/r/ZZ-TRI-FECTA/d/EM-2/config" in client.topics("unsubscribe")


def test_attach_errors_expire_when_they_stop_recurring(handler_factory, monkeypatch):
    h = handler_factory()
    h.record_gateway_error("CGW-1", json.dumps({"device_id": "CGW-1", "description": "boom"}))
    assert "status" in json.loads(h.get_state_payload("CGW-1")).get("gateway", {"status": 1})
    gw = h.devices_by_id["CGW-1"]
    gw["attach_error_seen"]["CGW-1"] -= module.ATTACH_ERROR_TTL_SEC + 1
    h._last_health_tick = 0
    h.tick()
    assert gw["attach_status"] is None


def test_attach_errors_for_unattached_proxies_do_not_expire(handler_factory):
    h = handler_factory()
    h.record_gateway_error("CGW-1", json.dumps({"device_id": "EM-1", "description": "not bound"}))
    gw = h.devices_by_id["CGW-1"]
    gw["attach_error_seen"]["EM-1"] -= module.ATTACH_ERROR_TTL_SEC + 1
    h._last_health_tick = 0
    h.tick()
    assert gw["attach_status"] is not None and "EM-1" in gw["attach_status"]["message"]


def test_errors_answering_the_new_session_survive_its_cleanup(handler_factory):
    h = handler_factory()
    h.record_gateway_error("CGW-1", json.dumps({"device_id": "EM-1", "description": "old"}), generation=1)
    h.clear_attach_errors(before_generation=2)
    assert h.devices_by_id["CGW-1"]["attach_status"] is None
    h.record_gateway_error("CGW-1", json.dumps({"device_id": "EM-1", "description": "new"}), generation=2)
    h.clear_attach_errors(before_generation=2)
    assert "new" in h.devices_by_id["CGW-1"]["attach_status"]["message"]


class _FakePublisher:
    """Minimal publisher double for main-loop wiring tests."""

    def __init__(self, reject_topics=()):
        self.connection_generation = 0
        self.config_queue = queue.Queue()
        self.errors = []
        self.published = []
        self.reject_topics = set(reject_topics)

    def drain_gateway_errors(self):
        drained, self.errors = self.errors, []
        return drained

    def maintain(self):
        pass

    def is_connected(self):
        return True

    def sync_proxy_devices(self, _ids):
        pass

    def publish(self, device_id, payload, topic="state", qos=1):
        import paho.mqtt.client as mqtt  # pylint: disable=import-outside-toplevel

        rc = mqtt.MQTT_ERR_NO_CONN if topic in self.reject_topics else mqtt.MQTT_ERR_SUCCESS
        if rc == mqtt.MQTT_ERR_SUCCESS:
            self.published.append((device_id, topic))
        return types.SimpleNamespace(rc=rc, is_published=lambda: True)


def test_rejected_state_publish_is_retried(handler_factory, logger, monkeypatch):
    h = handler_factory()
    h.handle_config("CGW-1", json.dumps({"version": "1.5.2", "timestamp": "2026-11-04T10:00:00Z"}))
    pub = _FakePublisher(reject_topics={"state"})
    base = [1000.0]
    monkeypatch.setattr(gcp_handler.time, "monotonic", lambda: base[0])
    gcp_handler.publish_due_udmi_messages(logger, pub, h)
    assert ("CGW-1", "state") not in pub.published
    pub.reject_topics.clear()
    base[0] += 5
    gcp_handler.publish_due_udmi_messages(logger, pub, h)
    assert ("CGW-1", "state") in pub.published


def test_reconnect_clears_old_attach_errors_and_resends_state(handler_factory, logger):
    h = handler_factory()
    h.record_gateway_error("CGW-1", json.dumps({"device_id": "EM-1", "description": "old"}), generation=0)
    pub = _FakePublisher()
    stop = threading.Event()
    original_tick = h.tick

    def tick_then_reconnect(*args, **kwargs):
        original_tick(*args, **kwargs)
        pub.connection_generation = 1  # paho re-connected during this loop pass
        stop.set()

    h.tick = tick_then_reconnect
    gcp_handler.run_gateway_loop(logger, types.SimpleNamespace(modbus__crc_check="strict"), pub, h, queue.Queue(), stop)
    assert h.devices_by_id["CGW-1"]["attach_status"] is None
    assert ("CGW-1", "state") in pub.published


def test_rejected_system_and_discovery_events_are_retried(handler_factory, logger):
    h = handler_factory()
    h.handle_config(
        "CGW-1",
        json.dumps(
            {
                "version": "1.5.2",
                "timestamp": "2026-11-16T10:00:00Z",
                "discovery": {"generation": "g-retry", "enumerations": {"features": "entries"}},
            }
        ),
    )
    pub = _FakePublisher(reject_topics={"events/system", "events/discovery"})
    gcp_handler.publish_due_udmi_messages(logger, pub, h)
    assert ("CGW-1", "events/system") not in pub.published
    assert ("CGW-1", "events/discovery") not in pub.published

    pub.reject_topics.clear()
    gcp_handler.publish_due_udmi_messages(logger, pub, h)
    assert ("CGW-1", "events/system") in pub.published
    assert ("CGW-1", "events/discovery") in pub.published


def test_config_validation_port_range_and_case_insensitive_redaction(tmp_path, caplog):
    site = write_site_model(tmp_path)
    bad_port_cfg = tmp_path / "bad_port.json"
    bad_port_cfg.write_text(
        json.dumps(
            {
                "google_cloud": {"mqtt_bridge_port": 70000},
                "site_details": {
                    "gateway_id": "CGW-1",
                    "proxy_ids": {"EM-1": {"type": "PM5561", "modbus_slave_id": 1}},
                },
                "environment_setup": {"udmi_site_model_path": str(site), "resources_path": RESOURCES_DIR},
            }
        )
    )
    with pytest.raises(GatewayConfigError, match="mqtt_bridge_port"):
        ConfigHandler(logging.getLogger("port"), types.SimpleNamespace(config_file=str(bad_port_cfg)))

    redacted = redact_secrets({"Password": "p1", "api_secret_token": "t1", "nested": [{"Passphrase": "p2"}]})
    assert redacted == {"Password": "***", "api_secret_token": "***", "nested": [{"Passphrase": "***"}]}


def test_explicit_registry_and_region_allow_missing_cloud_iot_config(tmp_path, caplog):
    empty_site = tmp_path / "no_cloud_iot_site"
    empty_site.mkdir()
    cfg = tmp_path / "cfg.json"
    cfg.write_text(
        json.dumps(
            {
                "google_cloud": {"iot_provider": "mqtt", "cloud_region": "us-west1"},
                "site_details": {
                    "registry_id": "REG-EXPLICIT",
                    "gateway_id": "CGW-1",
                    "proxy_ids": {"EM-1": {"type": "generic", "modbus_slave_id": 1}},
                },
                "environment_setup": {
                    "udmi_site_model_path": str(empty_site),
                    "resources_path": RESOURCES_DIR,
                    "state_dir": str(tmp_path / "state"),
                },
            }
        )
    )
    with caplog.at_level(logging.WARNING):
        loaded = ConfigHandler(logging.getLogger("explicit"), types.SimpleNamespace(config_file=str(cfg)))
    assert loaded.site_details__registry_id == "REG-EXPLICIT"
    assert loaded.google_cloud__cloud_region == "us-west1"
    assert "cloud_iot_config.json" in caplog.text


def test_internal_broker_invalid_host_logs_error_without_nameerror(caplog):
    from google_iot_core_gateway.internal_broker_subscriber.internal_broker_subscriber import (
        MosquittoMQTTSubscriber,
    )

    log = logging.getLogger("int-broker-err")
    with caplog.at_level(logging.ERROR):
        sub = MosquittoMQTTSubscriber(log, queue.Queue(), host="")
    assert sub.client is not None
    assert "Error preparing internal broker connection" in caplog.text


def test_jwt_warns_when_clock_is_unsynchronized(tmp_path, caplog, monkeypatch):
    from google_iot_core_gateway.utils import jwt_handler

    class _FakeDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.datetime(1970, 1, 1, 0, 1, 0, tzinfo=tz)

    monkeypatch.setattr(jwt_handler.datetime, "datetime", _FakeDateTime)
    log = logging.getLogger("jwt-clock")
    with caplog.at_level(logging.WARNING):
        create_jwt(log, "proj", write_rsa_key(tmp_path), "RS256")
    assert "unsynchronized" in caplog.text
