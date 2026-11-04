# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Tests closing the gaps found by mutation testing in the second review round."""

import datetime
import json
import logging
import queue
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
from test_publisher import RecordingClient, _publisher, _rsa_key


def test_jwt_claims_and_lifetime(logger, tmp_path):
    publisher = _publisher(logger, tmp_path, provider="gbos", private_key_file=_rsa_key(tmp_path),
                           jwt_expires_minutes=60)
    token = publisher.client._password.decode() if isinstance(publisher.client._password, bytes) else publisher.client._password
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == "proj"
    assert claims["exp"] - claims["iat"] == 3600


def test_short_jwt_lifetimes_do_not_cause_a_refresh_storm(logger, tmp_path):
    publisher = _publisher(logger, tmp_path, provider="gbos", private_key_file=_rsa_key(tmp_path),
                           jwt_expires_minutes=10)
    calls = []
    publisher._refresh_jwt_credentials = lambda: calls.append(1)
    publisher._jwt_exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)
    for _ in range(100):
        publisher.maintain()
    assert calls == []  # a fresh 10-minute token is not refreshed again and again


def test_secrets_are_redacted_from_config_logs(tmp_path, caplog):
    site = write_site_model(tmp_path)
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({
        "google_cloud": {"iot_provider": "mqtt", "mqtt_password": "s3cr3t-value"},
        "site_details": {"gateway_id": "CGW-2", "proxy_ids": {"EM-11": {"type": "PM5561", "modbus_slave_id": 1}}},
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
        "site_details": {"gateway_id": "CGW-2", "proxy_ids": {
            "EM-11": {"type": "PM5561", "modbus_slave_id": 1},
            "EM-12": {"type": "PM5111", "modbus_slave_id": 1}}},
        "environment_setup": {"udmi_site_model_path": str(site), "resources_path": RESOURCES_DIR},
    }))
    with pytest.raises(GatewayConfigError, match="modbus_slave_id 1"):
        ConfigHandler(logging.getLogger("dup"), types.SimpleNamespace(config_file=str(cfg)))


def test_frames_are_routed_to_the_right_meter(tmp_path, logger, monkeypatch):
    monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
    site = write_site_model(tmp_path, with_em12=True)
    h = module.UDMIHandler(logger, RESOURCES_DIR, str(site), config_wait_timeout_sec=0)
    h.add_device_to_dict(1, "EM-11", "PM5561", port="ttyM0")
    h.add_device_to_dict(2, "EM-12", "PM5111", port="ttyM0")
    q = queue.Queue()
    for slave in (1, 2):
        for req, resp in sim.build_slave_frames(slave, 1):
            q.put(json.dumps({"rtu_request": req.hex(), "rtu_response": resp.hex()}))
    process_payloads(logger, q, h)
    assert json.loads(h.get_state_payload("EM-11"))["system"]["serial_no"] == "52110011"
    assert json.loads(h.get_state_payload("EM-12"))["system"]["serial_no"] == "51110012"
    assert json.loads(h.get_state_payload("EM-12"))["system"]["hardware"]["model"] == "PM5111"


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
    publisher = _publisher(logger)
    client = RecordingClient()
    publisher.on_connect(client, None, {}, 0)
    publisher.client = client
    publisher.sync_proxy_devices(["EM-11"])
    assert "/r/UK-LON-GLAB/d/EM-12/detach" in client.topics("publish")
    assert "/r/UK-LON-GLAB/d/EM-12/config" in client.topics("unsubscribe")


def test_attach_errors_expire_when_they_stop_recurring(handler_factory, monkeypatch):
    h = handler_factory()
    h.record_gateway_error("CGW-2", json.dumps({"device_id": "CGW-2", "description": "boom"}))
    assert "status" in json.loads(h.get_state_payload("CGW-2")).get("gateway", {"status": 1})
    gw = h.devices_by_id["CGW-2"]
    gw["attach_error_seen"]["CGW-2"] -= module.ATTACH_ERROR_TTL_SEC + 1
    h._last_health_tick = 0
    h.tick()
    assert gw["attach_status"] is None
