# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Telemetry health, connectivity, identity publishing and config semantics."""

import json
import queue
import time

from google_iot_core_gateway.gcp_handler import process_payloads
from google_iot_core_gateway.udmi_handler import udmi_handler as module
from google_iot_core_gateway.udmi_handler.udmi_handler import (
    CATEGORY_GATEWAY_PROXY_CONNECT,
    CATEGORY_GATEWAY_SETUP_ATTACH,
    CATEGORY_POINTSET_POINT_INVALID,
    HEALTH_STATE_THROTTLE_SEC,
)
from conftest import RESOURCES_DIR, write_site_model
from helpers import config as _config, em11_config as _em11_config, exception_reply as _exception
from helpers import frame as _frame, state_of as _state


def _error(kind, slave=1):
    return {"slave_id": slave, "fc": 3, "start_register": 3000, "quantity": 2, "data": None,
            "unavailable": {}, "error": f"{kind} problem", "error_kind": kind, "exception_code": None}


def test_connect_status_does_not_flap_with_changing_errors(handler_factory):
    h = handler_factory(stale_timeout_sec=60)
    h.handle_config("EM-11", _em11_config())
    base = time.monotonic()
    h.record_modbus_payload(_frame({3028: 230.0, 3110: 50.0}, qty=84), now_mono=base)
    publishes = 0
    for second in range(61, 61 + 900):
        now = base + second
        h.record_modbus_payload(_error("crc" if second % 2 else "framing"), now_mono=now)
        h.tick(now)
        if h.pop_due_state_payload("EM-11", now_mono=now):
            publishes += 1
    assert publishes <= 3
    assert _state(h)["gateway"]["status"]["category"] == CATEGORY_GATEWAY_PROXY_CONNECT


def test_exception_replies_prove_the_meter_is_reachable(handler_factory):
    h = handler_factory(stale_timeout_sec=60)
    h.handle_config("EM-11", _em11_config())
    base = time.monotonic()
    for second in range(0, 200, 5):
        h.record_modbus_payload(_exception(0x02, 3020, 20), now_mono=base + second)
    h.tick(base + 200)
    state = _state(h)
    assert state["system"]["operation"]["operational"] is True
    assert "status" not in state["gateway"]
    assert state["pointset"]["points"]["line1_neutral_voltage_sensor"]["value_state"] == "failure"


def test_block_errors_only_hit_fully_contained_points_without_recent_reads(handler_factory):
    h = handler_factory()
    h.handle_config("EM-11", _em11_config())
    now = time.monotonic()
    # 3028-3029 only partly overlaps 3029-3040: the request would never have decoded it.
    h.record_modbus_payload(_exception(0x02, 3029, 12), now_mono=now)
    assert _state(h)["pointset"]["points"]["line1_neutral_voltage_sensor"].get("value_state") != "failure"
    # Read successfully by another request just before: the block error is not attributed.
    h.record_modbus_payload(_frame({3028: 230.0}, qty=2), now_mono=now + 1)
    h.record_modbus_payload(_exception(0x02, 3020, 20), now_mono=now + 2)
    assert _state(h)["pointset"]["points"]["line1_neutral_voltage_sensor"] == {}


def test_unit_id_from_gateway_target_is_used_for_refs(tmp_path, logger, monkeypatch):
    monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
    site = write_site_model(tmp_path, em11_localnet={"families": {"modbus": {"addr": "ttyM0"}}})
    meta_path = site / "devices" / "EM-11" / "metadata.json"
    meta = json.loads(meta_path.read_text())
    meta["gateway"]["target"]["unitid"] = "1"
    meta_path.write_text(json.dumps(meta))
    h = module.UDMIHandler(logger, RESOURCES_DIR, str(site), config_wait_timeout_sec=0)
    h.add_device_to_dict(1, "EM-11", "PM5561", port="ttyM0")
    h.handle_config("EM-11", _em11_config())
    h.record_modbus_payload(_frame({3028: 230.0, 3110: 50.0}, qty=84))
    assert _state(h)["pointset"]["points"] == {"line1_neutral_voltage_sensor": {}, "frequency_sensor": {}}


def test_identity_change_is_published(handler_factory):
    h = handler_factory()
    h.handle_config("EM-11", _em11_config())
    now = time.monotonic()
    assert h.pop_due_state_payload("EM-11", now_mono=now) is not None
    h.record_modbus_payload(_frame({130: 52110011}, start=130, qty=2), now_mono=now + 5)
    payload = h.pop_due_state_payload("EM-11", now_mono=now + 5)
    assert payload is not None
    assert json.loads(payload)["system"]["serial_no"] == "52110011"


def test_rejected_set_value_keeps_publishing_the_reading(handler_factory):
    h = handler_factory()
    h.handle_config("EM-11", _em11_config(points={"frequency_sensor": {"set_value": 49.0}}))
    h.record_modbus_payload(_frame({3110: 50.0}, start=3110, qty=2))
    assert _state(h)["pointset"]["points"]["frequency_sensor"]["value_state"] == "invalid"
    assert json.loads(h.get_event_point_payload("EM-11"))["points"] == {"frequency_sensor": {"present_value": 50.0}}


def test_unit_conversion_requests_are_rejected(handler_factory):
    h = handler_factory()
    h.handle_config("EM-11", _em11_config(points={"frequency_sensor": {"units": "Kilohertz"}}))
    h.record_modbus_payload(_frame({3110: 50.0}, start=3110, qty=2))
    status = _state(h)["pointset"]["points"]["frequency_sensor"]["status"]
    assert status["category"] == CATEGORY_POINTSET_POINT_INVALID
    assert json.loads(h.get_event_point_payload("EM-11"))["points"] == {}


def test_unit_spelling_differences_are_not_conversions(handler_factory):
    h = handler_factory()
    h.handle_config("EM-11", _em11_config(points={"frequency_sensor": {"units": "hertz"}}))
    h.record_modbus_payload(_frame({3110: 50.0}, start=3110, qty=2))
    assert _state(h)["pointset"]["points"]["frequency_sensor"] == {}


def test_config_without_points_uses_all_readable_points(handler_factory):
    h = handler_factory()
    h.handle_config("EM-11", _config("2026-11-04T10:00:00Z", pointset={"sample_rate_sec": 10}))
    assert len(_state(h)["pointset"]["points"]) == 42
    # An explicit empty points object is authoritative: no points.
    h.handle_config("EM-11", _config("2026-11-04T10:00:01Z", pointset={"sample_rate_sec": 10, "points": {}}))
    assert _state(h)["pointset"]["points"] == {}
    assert h.pop_due_pointset_event_payload("EM-11", now_mono=time.monotonic() + 60) is None


def test_unknown_proxy_ids_are_reported(handler_factory):
    h = handler_factory()
    h.handle_config("CGW-2", _config("2026-11-04T10:00:00Z", gateway={"proxy_ids": ["EM-11", "EM-99"]}))
    status = _state(h, "CGW-2")["gateway"]["status"]
    assert status["category"] == CATEGORY_GATEWAY_SETUP_ATTACH
    assert "EM-99" in status["message"]
    entries = json.loads(h.pop_due_system_event_payload("CGW-2"))["logentries"]
    assert any(e["category"] == CATEGORY_GATEWAY_SETUP_ATTACH and "EM-99" in e["message"] for e in entries)


def test_health_only_changes_are_rate_limited(handler_factory):
    h = handler_factory()
    h.handle_config("EM-11", _em11_config())
    now = time.monotonic()
    h.record_modbus_payload(_frame({3028: 230.0, 3110: 50.0}, qty=84), now_mono=now)
    assert h.pop_due_state_payload("EM-11", now_mono=now) is not None
    h.record_modbus_payload(_frame({3110: 50.0}, qty=84, unavailable=[3028]), now_mono=now + 3)
    assert h.pop_due_state_payload("EM-11", now_mono=now + 3) is None
    assert h.pop_due_state_payload("EM-11", now_mono=now + HEALTH_STATE_THROTTLE_SEC + 0.1) is not None


def test_gateway_metrics_default_to_schema_rate(handler_factory):
    h = handler_factory()
    h.handle_config("CGW-2", _config("2026-11-04T10:00:00Z"))
    h.pop_due_system_event_payload("CGW-2")
    payload = h.pop_due_system_event_payload("CGW-2", now_mono=time.monotonic() + 11)
    assert payload is not None and "metrics" in json.loads(payload)


def test_poison_message_does_not_stop_processing(handler_factory, logger):
    h = handler_factory()
    q = queue.Queue()
    q.put("[" * 100000 + "]" * 100000)  # RecursionError in json.loads
    q.put("not json at all")
    assert process_payloads(logger, q, h) == 2
