# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""UDMIHandler behaviour tests: config handling, data integrity, identity, restart, refs."""

import json
import logging
import time

import pytest

from google_iot_core_gateway.udmi_handler import udmi_handler as module
from google_iot_core_gateway.udmi_handler.udmi_handler import (
    CATEGORY_GATEWAY_PROXY_CONNECT,
    CATEGORY_GATEWAY_PROXY_TARGET,
    CATEGORY_GATEWAY_SETUP_ATTACH,
    CATEGORY_POINTSET_POINT_FAILURE,
    CATEGORY_POINTSET_POINT_INVALID,
    CATEGORY_SYSTEM_CONFIG_APPLY,
    CATEGORY_SYSTEM_CONFIG_PARSE,
    CATEGORY_SYSTEM_CONFIG_RECEIVE,
    GATEWAY_FEATURES,
    GATEWAY_HOST_POINTS,
    LEVEL_DEBUG,
    LEVEL_ERROR,
    LEVEL_WARNING,
    PROXY_FEATURES,
    group_fc_register_spans,
    parse_modbus_ref,
)
from conftest import META_METER_IDENTITY, RESOURCES_DIR, write_site_model
from google_iot_core_gateway.gcp_handler import process_payloads
from google_iot_core_gateway.modbus_gw.modbus_to_json import (
    append_modbus_crc16,
    decode_modbus_frame,
)
from helpers import config as _config, meter_config as _meter_config, exception_reply as _exception
from helpers import V, frame as _frame, state_of as _state


class TestConfigHandling:
    def test_broken_config_keeps_last_config_and_logs_parse_error(self, handler_factory):
        h = handler_factory()
        assert h.handle_config("CGW-1", _config("2026-11-04T10:00:00Z", system={"min_loglevel": LEVEL_DEBUG}))
        h.pop_due_system_event_payload("CGW-1")
        assert not h.handle_config("CGW-1", "{ broken json")
        entries = json.loads(h.pop_due_system_event_payload("CGW-1"))["logentries"]
        cats = [(e["category"], e["level"]) for e in entries]
        assert (CATEGORY_SYSTEM_CONFIG_RECEIVE, LEVEL_DEBUG) in cats
        assert (CATEGORY_SYSTEM_CONFIG_PARSE, LEVEL_ERROR) in cats
        assert all(cat != CATEGORY_SYSTEM_CONFIG_APPLY for cat, _ in cats)
        state = _state(h, "CGW-1")
        assert state["system"]["last_config"] == "2026-11-04T10:00:00Z"
        assert state["system"]["status"]["category"] == CATEGORY_SYSTEM_CONFIG_PARSE
        # A good config clears the status again.
        assert h.handle_config("CGW-1", _config("2026-11-04T10:00:05Z"))
        assert "status" not in _state(h, "CGW-1")["system"]

    def test_default_min_loglevel_is_notice(self, handler_factory):
        h = handler_factory()
        assert h.handle_config("CGW-1", json.dumps({"version": V, "timestamp": "2026-11-04T10:00:00Z"}))
        entries = json.loads(h.pop_due_system_event_payload("CGW-1"))["logentries"]
        assert [e["level"] for e in entries] == [300]  # only the NOTICE apply entry

    def test_subblock_parity_and_extra_fields(self, handler_factory):
        h = handler_factory()
        cfg = _config("2026-11-04T10:05:00Z", system={"min_loglevel": LEVEL_WARNING, "extra": 1},
                      localnet={"families": {"ether": {}}})
        assert h.handle_config("CGW-1", cfg)
        assert h.pop_due_system_event_payload("CGW-1") is None
        state = _state(h, "CGW-1")
        assert set(state) == {"version", "timestamp", "system", "localnet"}

    def test_failed_apply_leaves_device_untouched(self, handler_factory, monkeypatch):
        h = handler_factory()
        assert h.handle_config("EM-1", _meter_config())
        before = _state(h)
        dev = h.devices_by_id["EM-1"]
        before_loglevel = dev["min_loglevel"]
        # Fails in the gateway step, after system settings and subblocks were already processed.
        monkeypatch.setattr(h, "_validate_target", lambda dev, target: 1 / 0)
        failing = _config(
            "2026-11-04T11:00:00Z",
            system={"min_loglevel": LEVEL_DEBUG, "operation": {"mode": "active"}},
            gateway={"target": {"family": "modbus"}},
            pointset={"points": {"frequency_sensor": {}}},
        )
        assert not h.handle_config("EM-1", failing)
        after = _state(h)
        assert after["system"]["status"]["category"] == CATEGORY_SYSTEM_CONFIG_APPLY
        assert after["system"]["last_config"] == before["system"]["last_config"]
        assert after["pointset"] == before["pointset"]
        assert set(after) == set(before)  # localnet block (absent from the failing config) kept
        assert dev["min_loglevel"] == before_loglevel

    def test_unsupported_modes_are_reported_not_applied(self, handler_factory):
        h = handler_factory()
        assert h.handle_config("CGW-1", _config("2026-11-04T10:00:00Z", system={"operation": {"mode": "shutdown"}}))
        entries = json.loads(h.pop_due_system_event_payload("CGW-1"))["logentries"]
        assert any(e["level"] == LEVEL_WARNING and "shutdown" in e["message"] for e in entries)
        assert _state(h, "CGW-1")["system"]["operation"]["mode"] == "initial"
        assert not h.restart_requested


class TestRestart:
    def test_initial_then_active_then_real_restart_request(self, handler_factory):
        h = handler_factory(restart_count=4)
        state = _state(h, "CGW-1")
        assert state["system"]["operation"]["mode"] == "initial"
        assert state["system"]["operation"]["restart_count"] == 4
        assert h.handle_config("CGW-1", _config("2026-11-04T10:00:00Z", system={"operation": {"mode": "active"}}))
        assert _state(h, "CGW-1")["system"]["operation"]["mode"] == "active"
        assert not h.restart_requested
        assert h.handle_config("CGW-1", _config("2026-11-04T10:00:01Z", system={"operation": {"mode": "restart"}}))
        assert h.restart_requested
        # The running process does not pretend to have restarted.
        state = _state(h, "CGW-1")
        assert state["system"]["operation"]["mode"] == "active"
        assert state["system"]["operation"]["restart_count"] == 4

    def test_restart_config_after_restart_does_not_loop(self, handler_factory):
        h = handler_factory(restart_count=5)  # freshly restarted process, mode "initial"
        assert h.handle_config("CGW-1", _config("2026-11-04T10:00:00Z", system={"operation": {"mode": "restart"}}))
        assert not h.restart_requested
        assert _state(h, "CGW-1")["system"]["operation"]["mode"] == "initial"

    def test_proxies_do_not_claim_restart_support(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-1", _config("2026-11-04T10:00:00Z", system={"operation": {"mode": "restart"}}))
        assert not h.restart_requested
        assert "mode" not in _state(h)["system"]["operation"]


class TestIdentity:
    def test_proxy_identity_comes_from_meter_registers(self, handler_factory):
        h = handler_factory()
        state = _state(h)
        # The fixture site model has META_METER_IDENTITY; none of it may be echoed back.
        assert state["system"]["serial_no"] == "unknown"
        assert state["system"]["software"] == {}
        assert state["system"]["hardware"] == {"make": "Schneider Electric", "model": "PM5561"}
        assert META_METER_IDENTITY["serial_no"] not in json.dumps(state)
        h.record_modbus_payload(_frame({130: 987654321, 1637: 1103, 50: "PM5560", 70: "Schneider Electric"}, start=1, qty=2000))
        state = _state(h)
        assert state["system"]["serial_no"] == "987654321"
        assert state["system"]["software"] == {"firmware": "1103"}
        assert state["system"]["hardware"] == {"make": "Schneider Electric", "model": "PM5560"}

    def test_meter_serial_wins_over_configured_serial(self, site_dir, logger, monkeypatch):
        monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
        h = module.UDMIHandler(logger, RESOURCES_DIR, str(site_dir), config_wait_timeout_sec=0)
        h.add_device_to_dict(1, "EM-1", "PM5561", serial_no="CONFIGURED-1")
        assert _state(h)["system"]["serial_no"] == "CONFIGURED-1"
        h.record_modbus_payload(_frame({130: 42}, start=130, qty=2))
        assert _state(h)["system"]["serial_no"] == "42"

    def test_gateway_identity_is_never_read_from_site_model(self, handler_factory):
        h = handler_factory()
        system = _state(h, "CGW-1")["system"]
        assert system["serial_no"] == "GW-CONFIGURED"
        assert system["software"] == {"firmware": module.GATEWAY_SOFTWARE_VERSION}
        assert system["hardware"] == {"make": "Moxa", "model": "unknown"}
        for value in ("META-GW-SERIAL", "MetaMake", "0.0.1-meta"):
            assert value not in json.dumps(system)

    def test_gateway_hardware_defaults_are_flagged(self, site_dir, logger, monkeypatch, caplog):
        monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
        h = module.UDMIHandler(logger, RESOURCES_DIR, str(site_dir), config_wait_timeout_sec=0)
        with caplog.at_level(logging.WARNING):
            h.register_gateway("CGW-1", proxy_ids=[], serial_no="S1")
        assert "site_details.hardware" in caplog.text
        # No model is guessed: an undeclared gateway model is reported as unknown.
        assert _state(h, "CGW-1")["system"]["hardware"] == {"make": "Moxa", "model": "unknown"}

        caplog.clear()
        h = module.UDMIHandler(logger, RESOURCES_DIR, str(site_dir), config_wait_timeout_sec=0)
        with caplog.at_level(logging.WARNING):
            h.register_gateway("CGW-1", proxy_ids=[], serial_no="S1", hardware={"make": "Moxa", "model": "UC-8210"})
        assert "site_details.hardware" not in caplog.text
        assert _state(h, "CGW-1")["system"]["hardware"] == {"make": "Moxa", "model": "UC-8210"}


class TestLocalnet:
    def test_metadata_address_is_never_reported_if_host_lacks_it(self, monkeypatch):
        monkeypatch.setattr(module, "_list_host_interfaces", lambda: ([{"ifname": "eth0", "ether": "aa:bb:cc:dd:ee:ff"}], True))
        meta = {"families": {"ipv4": {"addr": "203.0.113.7"}, "ipv6": {"addr": "2001:db8::7"}}}
        assert module.detect_host_network_families(None, meta) == {"ether": {"addr": "aa:bb:cc:dd:ee:ff"}}

    def test_multi_nic_selection_uses_metadata_only_to_pick_interface(self, monkeypatch):
        interfaces = [
            {"ifname": "eth0", "ether": "00:00:00:00:00:01", "ipv4": "10.0.0.5"},
            {"ifname": "eth1", "ether": "00:00:00:00:00:02", "ipv4": "192.168.4.2"},
        ]
        monkeypatch.setattr(module, "_list_host_interfaces", lambda: (interfaces, True))
        meta = {"families": {"ipv4": {"addr": "192.168.4.2"}}}
        assert module.detect_host_network_families(None, meta) == {
            "ether": {"addr": "00:00:00:00:00:02"},
            "ipv4": {"addr": "192.168.4.2"},
        }
        assert module.detect_host_network_families("eth0", meta)["ipv4"] == {"addr": "10.0.0.5"}

    def test_proxy_localnet_uses_configured_port_only(self, handler_factory):
        assert handler_factory(port=None).devices_by_id["EM-1"]["localnet_families"] == {"modbus": {}}
        assert handler_factory(port="ttyM1").devices_by_id["EM-1"]["localnet_families"] == {"modbus": {"addr": "ttyM1"}}


class TestDataIntegrity:
    def test_fresh_values_are_published(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config())
        h.record_modbus_payload(_frame({3028: 230.5, 3110: 50.0}, start=3028, qty=84))
        ev = json.loads(h.get_event_point_payload("EM-1"))
        assert ev["points"] == {
            "line1_neutral_voltage_sensor": {"present_value": 230.5},
            "frequency_sensor": {"present_value": 50.0},
        }
        assert "partial_update" not in ev
        assert _state(h)["pointset"]["points"] == {"line1_neutral_voltage_sensor": {}, "frequency_sensor": {}}

    def test_points_initialize_then_fail_without_data(self, handler_factory):
        h = handler_factory(stale_timeout_sec=60)
        h.handle_config("EM-1", _meter_config())
        assert _state(h)["pointset"]["points"]["frequency_sensor"] == {"value_state": "initializing"}
        h.tick(time.monotonic() + 61)
        state = _state(h)
        point = state["pointset"]["points"]["frequency_sensor"]
        assert point["value_state"] == "failure"
        assert point["status"]["category"] == CATEGORY_POINTSET_POINT_FAILURE
        assert state["gateway"]["status"]["category"] == CATEGORY_GATEWAY_PROXY_CONNECT
        assert state["system"]["operation"]["operational"] is False

    def test_stale_values_are_not_republished(self, handler_factory):
        h = handler_factory(stale_timeout_sec=60)
        h.handle_config("EM-1", _meter_config())
        now = time.monotonic()
        h.record_modbus_payload(_frame({3028: 230.5, 3110: 50.0}, qty=84), now_mono=now)
        h.tick(now + 61)
        ev = json.loads(h.get_event_point_payload("EM-1", now_mono=now + 61))
        assert ev["points"] == {}
        assert ev["partial_update"] is True
        assert h.pop_due_pointset_event_payload("EM-1", now_mono=now + 61) is None
        # Recovery
        h.record_modbus_payload(_frame({3028: 231.0, 3110: 50.1}, qty=84), now_mono=now + 62)
        h.tick(now + 63)
        state = _state(h)
        assert state["system"]["operation"]["operational"] is True
        assert "status" not in state["gateway"]

    def test_not_available_register_fails_point_and_is_omitted(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config())
        h.record_modbus_payload(_frame({3028: 230.5, 3110: 50.0}, qty=84))
        h.record_modbus_payload(_frame({3110: 50.0}, qty=84, unavailable=[3028]))
        point = _state(h)["pointset"]["points"]["line1_neutral_voltage_sensor"]
        assert point["value_state"] == "failure"
        assert "not available" in point["status"]["message"]
        assert list(json.loads(h.get_event_point_payload("EM-1"))["points"]) == ["frequency_sensor"]

    def test_persistent_exception_fails_only_points_in_block(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config())
        h.record_modbus_payload(_frame({3110: 50.0}, start=3110, qty=2))
        h.record_modbus_payload(_exception(0x02, 3020, 20))
        points = _state(h)["pointset"]["points"]
        assert points["line1_neutral_voltage_sensor"]["value_state"] == "failure"
        assert "0x02" in points["line1_neutral_voltage_sensor"]["status"]["message"]
        assert points["frequency_sensor"] == {}

    def test_partial_failure_does_not_flap_state(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config())
        base = time.monotonic()
        publishes, with_error = 0, 0
        for second in range(180):
            now = base + second
            if second % 2 == 0:
                h.record_modbus_payload(_exception(0x02, 3020, 20), now_mono=now)
                h.record_modbus_payload(_frame({3110: 50.0}, start=3110, qty=2), now_mono=now)
            h.tick(now)
            payload = h.pop_due_state_payload("EM-1", now_mono=now)
            if payload:
                publishes += 1
                pt = json.loads(payload)["pointset"]["points"]["line1_neutral_voltage_sensor"]
                with_error += 1 if pt.get("value_state") == "failure" else 0
        assert publishes <= 3
        assert with_error >= 1

    def test_transient_exception_does_not_fail_points_immediately(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config())
        h.record_modbus_payload(_frame({3028: 230.0, 3110: 50.0}, qty=84))
        h.record_modbus_payload(_exception(0x0B, 3020, 20))
        assert _state(h)["pointset"]["points"]["line1_neutral_voltage_sensor"] == {}


class TestPointRefs:
    @pytest.mark.parametrize(
        "ref",
        [
            "3/3028/2?type=FLOAT32",
            "3/3028/2",
            "3/3028",
            "3/3028/2?type=FLOAT32&worder=HWF&border=MSB",
            "4/3028/2?type=FLOAT32",
            "modbus://ttyM0/1/3/3028/2?type=FLOAT32",
            "3028",
        ],
    )
    def test_valid_refs(self, handler_factory, ref):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config(points={"line1_neutral_voltage_sensor": {"ref": ref}}))
        h.record_modbus_payload(_frame({3028: 230.0}, qty=2))
        assert _state(h)["pointset"]["points"]["line1_neutral_voltage_sensor"] == {}

    @pytest.mark.parametrize(
        "ref",
        [
            "ref-1a2b",
            "16/3028?type=BOGUS",
            "6/3028/2",
            "3/3029/2?type=FLOAT32",
            "3/9999",
            "3/3028/4?type=FLOAT32",
            "3/3028/2?type=INT16",
            "3/3028/2?worder=LWF",
            "3/3028/2?scale=0.1",
            "modbus://ttyM9/1/3/3028/2",
            "modbus://ttyM0/2/3/3028/2",
            "1/3/3028/2?type=FLOAT32",
        ],
    )
    def test_invalid_refs_fail_the_point(self, handler_factory, ref):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config(points={"line1_neutral_voltage_sensor": {"ref": ref}}))
        h.record_modbus_payload(_frame({3028: 230.0}, qty=2))
        point = _state(h)["pointset"]["points"]["line1_neutral_voltage_sensor"]
        assert point["value_state"] == "failure"
        assert point["status"]["category"] == CATEGORY_POINTSET_POINT_FAILURE
        assert json.loads(h.get_event_point_payload("EM-1"))["points"] == {}

    def test_unit_id_required_without_localnet_context(self):
        assert parse_modbus_ref("1/3/3028/2", unit_from_context=False)["unitid"] == 1
        with pytest.raises(ValueError):
            parse_modbus_ref("3/3028/2?type=FLOAT32", unit_from_context=False)

    def test_unknown_and_writeback_points_are_invalid(self, handler_factory):
        h = handler_factory()
        h.handle_config(
            "EM-1",
            _meter_config(points={"not_a_point": {}, "frequency_sensor": {"set_value": 49.0}}),
        )
        points = _state(h)["pointset"]["points"]
        assert points["not_a_point"]["status"]["category"] == CATEGORY_POINTSET_POINT_INVALID
        assert points["frequency_sensor"]["value_state"] == "invalid"


class TestGatewayTarget:
    @pytest.mark.parametrize(
        "target",
        [{"family": "bacnet"}, {"family": "modbus", "addr": "addr-1234"}, {"family": "modbus", "unitid": "7"}],
    )
    def test_bad_targets(self, handler_factory, target):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config(target=target))
        assert _state(h)["gateway"]["status"]["category"] == CATEGORY_GATEWAY_PROXY_TARGET

    @pytest.mark.parametrize("addr", ["ttyM0", "1", "0x01"])
    def test_good_targets(self, handler_factory, addr):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config(target={"family": "modbus", "addr": addr}))
        assert "status" not in _state(h)["gateway"]

    def test_site_model_unitid_mismatch_is_reported(self, tmp_path, logger, monkeypatch):
        monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
        site = write_site_model(tmp_path, meter_localnet={"families": {"modbus": {"addr": "ttyM0", "unitid": "2"}}})
        h = module.UDMIHandler(logger, RESOURCES_DIR, str(site), config_wait_timeout_sec=0)
        h.add_device_to_dict(1, "EM-1", "PM5561", port="ttyM0")
        h.handle_config("EM-1", _meter_config())
        status = _state(h)["gateway"]["status"]
        assert status["category"] == CATEGORY_GATEWAY_PROXY_TARGET
        assert "unitid 2" in status["message"]

    def test_cloud_attach_errors_surface_and_clear(self, handler_factory):
        h = handler_factory()
        h.handle_config("CGW-1", _config("2026-11-04T10:00:00Z", gateway={"proxy_ids": ["EM-1"]}))
        h.record_gateway_error("CGW-1", json.dumps({"error_type": "GATEWAY_ATTACHMENT_ERROR", "device_id": "EM-1", "description": "not bound"}))
        status = _state(h, "CGW-1")["gateway"]["status"]
        assert status["category"] == CATEGORY_GATEWAY_SETUP_ATTACH
        assert "EM-1" in status["message"]
        h.handle_config("EM-1", _meter_config())
        assert "status" not in _state(h, "CGW-1")["gateway"]


class TestStatePublishing:
    def test_failed_publish_is_retried_and_reconnect_forces_state(self, handler_factory):
        h = handler_factory()
        h.handle_config("CGW-1", _config("2026-11-04T10:00:00Z"))
        now = time.monotonic()
        assert h.pop_due_state_payload("CGW-1", now_mono=now) is not None
        assert h.pop_due_state_payload("CGW-1", now_mono=now + 5) is None
        h.state_publish_failed("CGW-1")
        assert h.pop_due_state_payload("CGW-1", now_mono=now + 10) is not None
        h.force_republish_all()
        assert h.pop_due_state_payload("CGW-1", now_mono=now + 11) is None  # throttled
        assert h.pop_due_state_payload("CGW-1", now_mono=now + 14) is not None

    def test_reverted_change_is_not_republished(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-1", _meter_config())
        now = time.monotonic()
        h.record_modbus_payload(_frame({3028: 230.0, 3110: 50.0}, qty=84), now_mono=now)
        assert h.pop_due_state_payload("EM-1", now_mono=now) is not None
        h.handle_config("EM-1", _meter_config(target={"family": "bacnet"}))
        h.handle_config("EM-1", _meter_config())
        assert h.pop_due_state_payload("EM-1", now_mono=now + 5) is None

    def test_pending_logs_are_bounded(self, handler_factory):
        h = handler_factory()
        for i in range(500):
            h.handle_config("EM-1", _config(f"2026-11-04T10:{i // 60:02d}:{i % 60:02d}Z"))
        assert len(h.devices_by_id["EM-1"]["pending_logs"]) <= module.MAX_PENDING_LOGS


class TestEnumeration:
    def test_enumeration_reports_device_knowledge(self, handler_factory):
        h = handler_factory()
        h.handle_config(
            "EM-1",
            _config(
                "2026-11-04T10:00:00Z",
                discovery={"generation": "2026-11-04T10:00:00Z",
                           "enumerations": {"families": "details", "features": "details", "points": "details"}},
            ),
        )
        events = [json.loads(e) for e in h.pop_due_discovery_events("EM-1")]
        assert len(events) == 1
        event = events[0]
        assert event["features"] == PROXY_FEATURES
        assert event["families"] == {"modbus": {"addr": "ttyM0"}}
        assert len(event["points"]) == 42  # every point in the PM5561 register map
        assert event["points"]["line1_neutral_voltage_sensor"]["ref"] == "3/3028/2?type=FLOAT32"

        h.handle_config(
            "CGW-1",
            _config("2026-11-04T10:00:00Z", discovery={"generation": "g1", "enumerations": {"features": "entries"}}),
        )
        assert json.loads(h.pop_due_discovery_events("CGW-1")[0])["features"] == GATEWAY_FEATURES

    def test_unsupported_blobs_are_reported(self, handler_factory):
        h = handler_factory()
        h.handle_config("CGW-1", _config("2026-11-04T10:00:00Z", blobset={"blobs": {"_firmware_update": {"generation": "2026-11-04T09:00:00Z"}}}))
        blob = _state(h, "CGW-1")["blobset"]["blobs"]["_firmware_update"]
        assert blob["phase"] == "final"
        assert blob["status"]["level"] == LEVEL_ERROR

    def test_unsupported_alarms_carry_a_status_each(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-1", _config("2026-11-04T10:00:00Z", alarmset={"alarms": {"over_voltage": {}}}))
        alarm = _state(h, "EM-1")["alarmset"]["alarms"]["over_voltage"]
        assert alarm["value_state"] == "invalid"
        assert alarm["status"]["category"] == CATEGORY_SYSTEM_CONFIG_APPLY
        assert alarm["status"]["level"] == LEVEL_ERROR
        assert "over_voltage" in alarm["status"]["message"]


class TestDatapointMapping:
    @staticmethod
    def _rtu_msg(slave_id: int, start_reg: int, values_bytes: bytes) -> str:
        import struct

        qty = len(values_bytes) // 2
        req = append_modbus_crc16(struct.pack(">BBHH", slave_id, 3, start_reg - 1, qty))
        resp = append_modbus_crc16(struct.pack(">BBB", slave_id, 3, len(values_bytes)) + values_bytes)
        return json.dumps({"rtu_request": req.hex(), "rtu_response": resp.hex()})

    def test_point_can_be_renamed_preserving_ref(self, handler_factory):
        h = handler_factory()
        h.record_modbus_payload(_frame({3028: 230.5, 3110: 50.0}, start=3028, qty=84))
        h.handle_config(
            "EM-1",
            _meter_config(points={"phase_a_voltage_sensor": {"ref": "3/3028/2?type=FLOAT32", "units": "Volts"}}),
        )
        assert _state(h)["pointset"]["points"] == {"phase_a_voltage_sensor": {}}
        ev = json.loads(h.get_event_point_payload("EM-1"))
        assert ev["points"] == {"phase_a_voltage_sensor": {"present_value": 230.5}}

    def test_existing_point_can_be_remapped_via_ref(self, handler_factory):
        h = handler_factory()
        h.record_modbus_payload(_frame({3028: 230.5, 3030: 232.25}, start=3028, qty=4))
        h.handle_config(
            "EM-1",
            _meter_config(points={"line1_neutral_voltage_sensor": {"ref": "3/3030/2?type=FLOAT32", "units": "Volts"}}),
        )
        ev = json.loads(h.get_event_point_payload("EM-1"))
        assert ev["points"] == {"line1_neutral_voltage_sensor": {"present_value": 232.25}}

    def test_dynamic_unmapped_register_decodes_from_raw_rtu_frame(self, handler_factory, logger):
        import queue
        import struct

        h = handler_factory()
        h.handle_config(
            "EM-1",
            _meter_config(points={"extra_power_sensor": {"ref": "3/4500/2?type=FLOAT32", "units": "Kilowatts"}}),
        )
        assert _state(h)["pointset"]["points"] == {"extra_power_sensor": {"value_state": "initializing"}}
        q = queue.Queue()
        q.put(self._rtu_msg(1, 4500, struct.pack(">f", 12.5)))
        assert process_payloads(logger, q, h) == 1
        assert _state(h)["pointset"]["points"] == {"extra_power_sensor": {}}
        assert json.loads(h.get_event_point_payload("EM-1"))["points"] == {
            "extra_power_sensor": {"present_value": 12.5}
        }

    def test_generic_device_without_metadata_works_from_cloud_config_unitid(
        self, site_dir, logger, monkeypatch
    ):
        import queue
        import struct

        monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
        h = module.UDMIHandler(logger, RESOURCES_DIR, str(site_dir), config_wait_timeout_sec=0)
        assert h.add_device_to_dict(
            4,
            "GEN-1",
            "generic",
            port="ttyM1",
            hardware={"make": "Acme", "model": "CustomMeter"},
        )
        assert _state(h, "GEN-1")["system"]["hardware"] == {"make": "Acme", "model": "CustomMeter"}

        cfg = _config(
            "2026-11-16T12:00:00Z",
            gateway={"target": {"family": "modbus", "addr": "ttyM1", "unitid": "4"}},
            pointset={
                "sample_rate_sec": 10,
                "points": {"custom_temp_sensor": {"ref": "3/100/1?type=INT16", "units": "Celsius"}},
            },
        )
        assert h.handle_config("GEN-1", cfg)
        q = queue.Queue()
        q.put(self._rtu_msg(4, 100, struct.pack(">h", 245)))
        assert process_payloads(logger, q, h) == 1
        assert _state(h, "GEN-1")["pointset"]["points"] == {"custom_temp_sensor": {}}
        assert json.loads(h.get_event_point_payload("GEN-1"))["points"] == {
            "custom_temp_sensor": {"present_value": 245}
        }


def test_clock_step_back_resynchronizes_timestamps(handler_factory, monkeypatch, caplog):
    h = handler_factory()
    fake_now = [1_800_000_000.0]
    monkeypatch.setattr(module.time, "time", lambda: fake_now[0])
    t1 = h.get_timestamp()
    # Small jitter (< 5s): stay strictly monotonic.
    fake_now[0] -= 1.0
    t2 = h.get_timestamp()
    assert t2 > t1
    # Large backwards NTP jump (>= 5s): resynchronize to the real clock.
    fake_now[0] -= 60.0
    with caplog.at_level(logging.WARNING):
        t3 = h.get_timestamp()
    assert t3 < t1
    assert "stepped backwards" in caplog.text


class TestFC04AndDecoderMaps:
    def test_group_fc_register_spans_groups_per_fc(self):
        grouped = group_fc_register_spans([(4, 200, 2), (3, 100, 1), (4, 202, 2), (3, 101, 2)])
        assert grouped == [(3, 100, 3), (4, 200, 4)]

    def test_canonical_point_ref_uses_fc4_and_omits_host_metrics(self, handler_factory):
        handler = handler_factory()
        dev = handler.devices_by_id["EM-1"]
        assert (
            handler._canonical_point_ref(
                dev, {"register": 3028, "num_registers": 2, "modbus_type": "FLOAT32", "fc": 4}
            )
            == "4/3028/2?type=FLOAT32"
        )
        assert (
            handler._canonical_point_ref(dev, {"host_metric": "mem_free_mb", "units": "Megabytes"})
            is None
        )

    def test_decoder_fc_key_precedence_and_isolation(self, handler_factory):
        import struct

        handler = handler_factory()
        handler.handle_config(
            "EM-1",
            _meter_config(
                points={
                    "holding_v": {"ref": "3/3028/2?type=FLOAT32"},
                    "input_v": {"ref": "4/3028/2?type=FLOAT32"},
                    "holding_extra": {"ref": "3/4500/1?type=INT16"},
                    "input_extra": {"ref": "4/4500/2?type=FLOAT32"},
                }
            ),
        )
        slave_to_type, dbo_maps = handler.get_decoder_maps()
        dev_map = dbo_maps[slave_to_type[1]]
        assert "3:4500" in dev_map and "4:4500" in dev_map

        req_fc3 = append_modbus_crc16(struct.pack(">BBHH", 1, 3, 4499, 1))
        resp_fc3 = append_modbus_crc16(struct.pack(">BBB", 1, 3, 2) + struct.pack(">h", 77))
        decoded_fc3 = decode_modbus_frame(
            req_fc3, resp_fc3, slave_to_type=slave_to_type, dbo_maps=dbo_maps
        )
        assert decoded_fc3["fc"] == 3
        assert decoded_fc3["data"] == {"4500": 77}

        req_fc4 = append_modbus_crc16(struct.pack(">BBHH", 1, 4, 4499, 2))
        resp_fc4 = append_modbus_crc16(struct.pack(">BBB", 1, 4, 4) + struct.pack(">f", 12.5))
        decoded_fc4 = decode_modbus_frame(
            req_fc4, resp_fc4, slave_to_type=slave_to_type, dbo_maps=dbo_maps
        )
        assert decoded_fc4["fc"] == 4
        assert decoded_fc4["data"] == {"4500": 12.5}

        handler.record_modbus_payload(decoded_fc3)
        handler.record_modbus_payload(decoded_fc4)
        points = json.loads(handler.get_event_point_payload("EM-1"))["points"]
        assert points == {
            "holding_extra": {"present_value": 77},
            "input_extra": {"present_value": 12.5},
        }

    def test_fc04_same_address_different_type_and_fc03_exception_do_not_collide(self, handler_factory):
        import struct

        handler = handler_factory()
        handler.error_grace_sec = 0.0
        # 3028 is FLOAT32 (2 regs) in PM5561 FC03 map; FC04 at 3028 can be a distinct INT16 point.
        handler.handle_config(
            "EM-1",
            _meter_config(points={"input_word_3028": {"ref": "4/3028/1?type=INT16", "units": "Amperes"}}),
        )
        # An FC03 exception at 3028 must not fail the FC04 point even when FC03 is unconfigured.
        handler.record_modbus_payload(_exception(0x02, 3028, 2))
        assert _state(handler)["pointset"]["points"]["input_word_3028"] == {"value_state": "initializing"}

        slave_to_type, dbo_maps = handler.get_decoder_maps()
        req_fc4 = append_modbus_crc16(struct.pack(">BBHH", 1, 4, 3027, 1))
        resp_fc4 = append_modbus_crc16(struct.pack(">BBB", 1, 4, 2) + struct.pack(">h", -42))
        decoded_fc4 = decode_modbus_frame(
            req_fc4, resp_fc4, slave_to_type=slave_to_type, dbo_maps=dbo_maps
        )
        assert decoded_fc4["data"] == {"3028": -42}
        handler.record_modbus_payload(decoded_fc4)
        assert _state(handler)["pointset"]["points"]["input_word_3028"] == {}
        assert json.loads(handler.get_event_point_payload("EM-1"))["points"] == {
            "input_word_3028": {"present_value": -42}
        }


class TestGatewayHostPointset:
    def test_gateway_points_default_off_matches_v4_4_0(self, handler_factory):
        handler = handler_factory()
        state = _state(handler, "CGW-1")
        assert "pointset" not in state
        assert "pointset" not in handler.devices_by_id["CGW-1"]["supported_features"]
        assert handler.pop_due_pointset_event_payload("CGW-1", now_mono=time.monotonic() + 60) is None

    def test_gateway_points_opt_in_publishes_live_metrics_and_handles_configs(
        self, site_dir, logger, monkeypatch
    ):
        monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
        monkeypatch.setattr(
            module,
            "_collect_host_metrics",
            lambda: {
                "mem_free_mb": 512.5,
                "mem_total_mb": 1024.0,
                "store_free_mb": 2048.25,
                "store_total_mb": 4096.0,
                "system_load": 0.42,
            },
        )
        handler = module.UDMIHandler(logger, RESOURCES_DIR, str(site_dir), config_wait_timeout_sec=0)
        assert handler.register_gateway(
            "CGW-1",
            proxy_ids=[],
            serial_no="GW-HOST",
            restart_count=7,
            gateway_points_enabled=True,
        )

        gw_dev = handler.devices_by_id["CGW-1"]
        assert gw_dev["supported_features"]["pointset"] == {"stage": "stable"}
        assert gw_dev["supported_features"]["enumeration.pointset"] == {"stage": "preview"}

        # Before first cloud config, all 6 host points are active and publish numeric values.
        state = _state(handler, "CGW-1")
        assert set(state["pointset"]["points"]) == set(GATEWAY_HOST_POINTS)
        for pt_state in state["pointset"]["points"].values():
            assert pt_state == {}

        ev = json.loads(handler.get_event_point_payload("CGW-1"))
        assert ev["points"] == {
            "mem_free_mb": {"present_value": 512.5},
            "mem_total_mb": {"present_value": 1024.0},
            "store_free_mb": {"present_value": 2048.25},
            "store_total_mb": {"present_value": 4096.0},
            "system_load": {"present_value": 0.42},
            "restart_count": {"present_value": 7},
        }
        for entry in ev["points"].values():
            val = entry["present_value"]
            assert isinstance(val, (int, float)) and not isinstance(val, bool)

        # Sample rate & sample limit honored; pointset_remove_point, extraneous, set_value, bad ref.
        cfg = _config(
            "2026-11-16T12:00:00Z",
            pointset={
                "sample_rate_sec": 5,
                "sample_limit_sec": 5,
                "points": {
                    "mem_free_mb": {},
                    "restart_count": {"set_value": 1},
                    "system_load": {"ref": "bad-ref"},
                    "bogus_metric": {},
                },
            },
            discovery={
                "generation": "2026-11-16T12:00:00Z",
                "enumerations": {"features": "details", "points": "details"},
            },
        )
        assert handler.handle_config("CGW-1", cfg)
        now = time.monotonic()
        assert handler.pop_due_pointset_event_payload("CGW-1", now_mono=now) is None
        due_payload = handler.pop_due_pointset_event_payload("CGW-1", now_mono=now + 6.0)
        assert due_payload is not None
        due_points = json.loads(due_payload)["points"]
        # restart_count has set_value (invalid in state) but still publishes present_value;
        # mem_total_mb / store_* were removed; bogus_metric & system_load omitted.
        assert due_points == {
            "mem_free_mb": {"present_value": 512.5},
            "restart_count": {"present_value": 7},
        }

        gw_state_points = _state(handler, "CGW-1")["pointset"]["points"]
        assert set(gw_state_points) == {"mem_free_mb", "restart_count", "system_load", "bogus_metric"}
        assert gw_state_points["mem_free_mb"] == {}
        assert gw_state_points["restart_count"]["value_state"] == "invalid"
        assert gw_state_points["system_load"]["value_state"] == "failure"
        assert gw_state_points["bogus_metric"]["value_state"] == "invalid"

        # Self-enumeration lists host points with units and cleanly omits "ref".
        disc_events = [json.loads(item) for item in handler.pop_due_discovery_events("CGW-1")]
        assert len(disc_events) == 1
        disc = disc_events[0]
        assert "pointset" in disc["features"]
        assert "enumeration.pointset" in disc["features"]
        assert set(disc["points"]) == set(GATEWAY_HOST_POINTS)
        for pt_name, pt_units in GATEWAY_HOST_POINTS.items():
            assert disc["points"][pt_name] == {"units": pt_units}
            assert "ref" not in disc["points"][pt_name]

    def test_gateway_points_auto_enabled_from_metadata_pointset(self, tmp_path, logger, monkeypatch):
        monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
        monkeypatch.setattr(
            module,
            "_collect_host_metrics",
            lambda: {
                "mem_free_mb": 256.0,
                "mem_total_mb": 1024.0,
                "store_free_mb": 1000.0,
                "store_total_mb": 2000.0,
                "system_load": 0.1,
            },
        )
        site = write_site_model(tmp_path)
        gw_meta_path = site / "devices" / "CGW-1" / "metadata.json"
        gw_meta = json.loads(gw_meta_path.read_text(encoding="utf-8"))
        gw_meta["pointset"] = {"points": {"mem_free_mb": {}, "restart_count": {}}}
        gw_meta_path.write_text(json.dumps(gw_meta), encoding="utf-8")

        handler = module.UDMIHandler(logger, RESOURCES_DIR, str(site), config_wait_timeout_sec=0)
        assert handler.register_gateway("CGW-1", proxy_ids=[], serial_no="GW-META", restart_count=3)
        assert _state(handler, "CGW-1")["pointset"]["points"] == {"mem_free_mb": {}, "restart_count": {}}
        assert json.loads(handler.get_event_point_payload("CGW-1"))["points"] == {
            "mem_free_mb": {"present_value": 256.0},
            "restart_count": {"present_value": 3},
        }
