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
    LEVEL_DEBUG,
    LEVEL_ERROR,
    LEVEL_WARNING,
    PROXY_FEATURES,
    parse_modbus_ref,
)
from conftest import META_METER_IDENTITY, RESOURCES_DIR, write_site_model
from helpers import config as _config, em11_config as _em11_config, exception_reply as _exception
from helpers import V, frame as _frame, state_of as _state


class TestConfigHandling:
    def test_broken_config_keeps_last_config_and_logs_parse_error(self, handler_factory):
        h = handler_factory()
        assert h.handle_config("CGW-2", _config("2026-11-04T10:00:00Z", system={"min_loglevel": LEVEL_DEBUG}))
        h.pop_due_system_event_payload("CGW-2")
        assert not h.handle_config("CGW-2", "{ broken json")
        entries = json.loads(h.pop_due_system_event_payload("CGW-2"))["logentries"]
        cats = [(e["category"], e["level"]) for e in entries]
        assert (CATEGORY_SYSTEM_CONFIG_RECEIVE, LEVEL_DEBUG) in cats
        assert (CATEGORY_SYSTEM_CONFIG_PARSE, LEVEL_ERROR) in cats
        assert all(cat != CATEGORY_SYSTEM_CONFIG_APPLY for cat, _ in cats)
        state = _state(h, "CGW-2")
        assert state["system"]["last_config"] == "2026-11-04T10:00:00Z"
        assert state["system"]["status"]["category"] == CATEGORY_SYSTEM_CONFIG_PARSE
        # A good config clears the status again.
        assert h.handle_config("CGW-2", _config("2026-11-04T10:00:05Z"))
        assert "status" not in _state(h, "CGW-2")["system"]

    def test_default_min_loglevel_is_notice(self, handler_factory):
        h = handler_factory()
        assert h.handle_config("CGW-2", json.dumps({"version": V, "timestamp": "2026-11-04T10:00:00Z"}))
        entries = json.loads(h.pop_due_system_event_payload("CGW-2"))["logentries"]
        assert [e["level"] for e in entries] == [300]  # only the NOTICE apply entry

    def test_subblock_parity_and_extra_fields(self, handler_factory):
        h = handler_factory()
        cfg = _config("2026-11-04T10:05:00Z", system={"min_loglevel": LEVEL_WARNING, "extra": 1},
                      localnet={"families": {"ether": {}}})
        assert h.handle_config("CGW-2", cfg)
        assert h.pop_due_system_event_payload("CGW-2") is None
        state = _state(h, "CGW-2")
        assert set(state) == {"version", "timestamp", "system", "localnet"}

    def test_failed_apply_leaves_device_untouched(self, handler_factory, monkeypatch):
        h = handler_factory()
        assert h.handle_config("EM-11", _em11_config())
        before = _state(h)
        dev = h.devices_by_id["EM-11"]
        before_loglevel = dev["min_loglevel"]
        # Fails in the gateway step, after system settings and subblocks were already processed.
        monkeypatch.setattr(h, "_validate_target", lambda dev, target: 1 / 0)
        failing = _config(
            "2026-11-04T11:00:00Z",
            system={"min_loglevel": LEVEL_DEBUG, "operation": {"mode": "active"}},
            gateway={"target": {"family": "modbus"}},
            pointset={"points": {"frequency_sensor": {}}},
        )
        assert not h.handle_config("EM-11", failing)
        after = _state(h)
        assert after["system"]["status"]["category"] == CATEGORY_SYSTEM_CONFIG_APPLY
        assert after["system"]["last_config"] == before["system"]["last_config"]
        assert after["pointset"] == before["pointset"]
        assert set(after) == set(before)  # localnet block (absent from the failing config) kept
        assert dev["min_loglevel"] == before_loglevel

    def test_unsupported_modes_are_reported_not_applied(self, handler_factory):
        h = handler_factory()
        assert h.handle_config("CGW-2", _config("2026-11-04T10:00:00Z", system={"operation": {"mode": "shutdown"}}))
        entries = json.loads(h.pop_due_system_event_payload("CGW-2"))["logentries"]
        assert any(e["level"] == LEVEL_WARNING and "shutdown" in e["message"] for e in entries)
        assert _state(h, "CGW-2")["system"]["operation"]["mode"] == "initial"
        assert not h.restart_requested


class TestRestart:
    def test_initial_then_active_then_real_restart_request(self, handler_factory):
        h = handler_factory(restart_count=4)
        state = _state(h, "CGW-2")
        assert state["system"]["operation"]["mode"] == "initial"
        assert state["system"]["operation"]["restart_count"] == 4
        assert h.handle_config("CGW-2", _config("2026-11-04T10:00:00Z", system={"operation": {"mode": "active"}}))
        assert _state(h, "CGW-2")["system"]["operation"]["mode"] == "active"
        assert not h.restart_requested
        assert h.handle_config("CGW-2", _config("2026-11-04T10:00:01Z", system={"operation": {"mode": "restart"}}))
        assert h.restart_requested
        # The running process does not pretend to have restarted.
        state = _state(h, "CGW-2")
        assert state["system"]["operation"]["mode"] == "active"
        assert state["system"]["operation"]["restart_count"] == 4

    def test_restart_config_after_restart_does_not_loop(self, handler_factory):
        h = handler_factory(restart_count=5)  # freshly restarted process, mode "initial"
        assert h.handle_config("CGW-2", _config("2026-11-04T10:00:00Z", system={"operation": {"mode": "restart"}}))
        assert not h.restart_requested
        assert _state(h, "CGW-2")["system"]["operation"]["mode"] == "initial"

    def test_proxies_do_not_claim_restart_support(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-11", _config("2026-11-04T10:00:00Z", system={"operation": {"mode": "restart"}}))
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
        h.add_device_to_dict(1, "EM-11", "PM5561", serial_no="CONFIGURED-1")
        assert _state(h)["system"]["serial_no"] == "CONFIGURED-1"
        h.record_modbus_payload(_frame({130: 42}, start=130, qty=2))
        assert _state(h)["system"]["serial_no"] == "42"

    def test_gateway_identity_is_never_read_from_site_model(self, handler_factory):
        h = handler_factory()
        system = _state(h, "CGW-2")["system"]
        assert system["serial_no"] == "CGW2-CONFIGURED"
        assert system["software"] == {"firmware": module.GATEWAY_SOFTWARE_VERSION}
        assert system["hardware"] == {"make": "Moxa", "model": "UC8220"}
        for value in ("META-GW-SERIAL", "MetaMake", "0.0.1-meta"):
            assert value not in json.dumps(system)

    def test_gateway_hardware_defaults_are_flagged(self, site_dir, logger, monkeypatch, caplog):
        monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
        h = module.UDMIHandler(logger, RESOURCES_DIR, str(site_dir), config_wait_timeout_sec=0)
        with caplog.at_level(logging.WARNING):
            h.register_gateway("CGW-2", proxy_ids=[], serial_no="S1")
        assert "site_details.hardware" in caplog.text

        caplog.clear()
        h = module.UDMIHandler(logger, RESOURCES_DIR, str(site_dir), config_wait_timeout_sec=0)
        with caplog.at_level(logging.WARNING):
            h.register_gateway("CGW-2", proxy_ids=[], serial_no="S1", hardware={"make": "Moxa", "model": "UC-8210"})
        assert "site_details.hardware" not in caplog.text
        assert _state(h, "CGW-2")["system"]["hardware"] == {"make": "Moxa", "model": "UC-8210"}


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
        assert handler_factory(port=None).devices_by_id["EM-11"]["localnet_families"] == {"modbus": {}}
        assert handler_factory(port="ttyM1").devices_by_id["EM-11"]["localnet_families"] == {"modbus": {"addr": "ttyM1"}}


class TestDataIntegrity:
    def test_fresh_values_are_published(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-11", _em11_config())
        h.record_modbus_payload(_frame({3028: 230.5, 3110: 50.0}, start=3028, qty=84))
        ev = json.loads(h.get_event_point_payload("EM-11"))
        assert ev["points"] == {
            "line1_neutral_voltage_sensor": {"present_value": 230.5},
            "frequency_sensor": {"present_value": 50.0},
        }
        assert "partial_update" not in ev
        assert _state(h)["pointset"]["points"] == {"line1_neutral_voltage_sensor": {}, "frequency_sensor": {}}

    def test_points_initialize_then_fail_without_data(self, handler_factory):
        h = handler_factory(stale_timeout_sec=60)
        h.handle_config("EM-11", _em11_config())
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
        h.handle_config("EM-11", _em11_config())
        now = time.monotonic()
        h.record_modbus_payload(_frame({3028: 230.5, 3110: 50.0}, qty=84), now_mono=now)
        h.tick(now + 61)
        ev = json.loads(h.get_event_point_payload("EM-11", now_mono=now + 61))
        assert ev["points"] == {}
        assert ev["partial_update"] is True
        assert h.pop_due_pointset_event_payload("EM-11", now_mono=now + 61) is None
        # Recovery
        h.record_modbus_payload(_frame({3028: 231.0, 3110: 50.1}, qty=84), now_mono=now + 62)
        h.tick(now + 63)
        state = _state(h)
        assert state["system"]["operation"]["operational"] is True
        assert "status" not in state["gateway"]

    def test_not_available_register_fails_point_and_is_omitted(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-11", _em11_config())
        h.record_modbus_payload(_frame({3028: 230.5, 3110: 50.0}, qty=84))
        h.record_modbus_payload(_frame({3110: 50.0}, qty=84, unavailable=[3028]))
        point = _state(h)["pointset"]["points"]["line1_neutral_voltage_sensor"]
        assert point["value_state"] == "failure"
        assert "not available" in point["status"]["message"]
        assert list(json.loads(h.get_event_point_payload("EM-11"))["points"]) == ["frequency_sensor"]

    def test_persistent_exception_fails_only_points_in_block(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-11", _em11_config())
        h.record_modbus_payload(_frame({3110: 50.0}, start=3110, qty=2))
        h.record_modbus_payload(_exception(0x02, 3020, 20))
        points = _state(h)["pointset"]["points"]
        assert points["line1_neutral_voltage_sensor"]["value_state"] == "failure"
        assert "0x02" in points["line1_neutral_voltage_sensor"]["status"]["message"]
        assert points["frequency_sensor"] == {}

    def test_partial_failure_does_not_flap_state(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-11", _em11_config())
        base = time.monotonic()
        publishes, with_error = 0, 0
        for second in range(180):
            now = base + second
            if second % 2 == 0:
                h.record_modbus_payload(_exception(0x02, 3020, 20), now_mono=now)
                h.record_modbus_payload(_frame({3110: 50.0}, start=3110, qty=2), now_mono=now)
            h.tick(now)
            payload = h.pop_due_state_payload("EM-11", now_mono=now)
            if payload:
                publishes += 1
                pt = json.loads(payload)["pointset"]["points"]["line1_neutral_voltage_sensor"]
                with_error += 1 if pt.get("value_state") == "failure" else 0
        assert publishes <= 3
        assert with_error >= 1

    def test_transient_exception_does_not_fail_points_immediately(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-11", _em11_config())
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
        h.handle_config("EM-11", _em11_config(points={"line1_neutral_voltage_sensor": {"ref": ref}}))
        h.record_modbus_payload(_frame({3028: 230.0}, qty=2))
        assert _state(h)["pointset"]["points"]["line1_neutral_voltage_sensor"] == {}

    @pytest.mark.parametrize(
        "ref",
        [
            "ref-1a2b",
            "16/3028?type=BOGUS",
            "6/3028/2",
            "3/3030/2?type=FLOAT32",
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
        h.handle_config("EM-11", _em11_config(points={"line1_neutral_voltage_sensor": {"ref": ref}}))
        h.record_modbus_payload(_frame({3028: 230.0}, qty=2))
        point = _state(h)["pointset"]["points"]["line1_neutral_voltage_sensor"]
        assert point["value_state"] == "failure"
        assert point["status"]["category"] == CATEGORY_POINTSET_POINT_FAILURE
        assert json.loads(h.get_event_point_payload("EM-11"))["points"] == {}

    def test_unit_id_required_without_localnet_context(self):
        assert parse_modbus_ref("1/3/3028/2", unit_from_context=False)["unitid"] == 1
        with pytest.raises(ValueError):
            parse_modbus_ref("3/3028/2?type=FLOAT32", unit_from_context=False)

    def test_unknown_and_writeback_points_are_invalid(self, handler_factory):
        h = handler_factory()
        h.handle_config(
            "EM-11",
            _em11_config(points={"not_a_point": {}, "frequency_sensor": {"set_value": 49.0}}),
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
        h.handle_config("EM-11", _em11_config(target=target))
        assert _state(h)["gateway"]["status"]["category"] == CATEGORY_GATEWAY_PROXY_TARGET

    @pytest.mark.parametrize("addr", ["ttyM0", "1", "0x01"])
    def test_good_targets(self, handler_factory, addr):
        h = handler_factory()
        h.handle_config("EM-11", _em11_config(target={"family": "modbus", "addr": addr}))
        assert "status" not in _state(h)["gateway"]

    def test_site_model_unitid_mismatch_is_reported(self, tmp_path, logger, monkeypatch):
        monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
        site = write_site_model(tmp_path, em11_localnet={"families": {"modbus": {"addr": "ttyM0", "unitid": "2"}}})
        h = module.UDMIHandler(logger, RESOURCES_DIR, str(site), config_wait_timeout_sec=0)
        h.add_device_to_dict(1, "EM-11", "PM5561", port="ttyM0")
        h.handle_config("EM-11", _em11_config())
        status = _state(h)["gateway"]["status"]
        assert status["category"] == CATEGORY_GATEWAY_PROXY_TARGET
        assert "unitid 2" in status["message"]

    def test_cloud_attach_errors_surface_and_clear(self, handler_factory):
        h = handler_factory()
        h.handle_config("CGW-2", _config("2026-11-04T10:00:00Z", gateway={"proxy_ids": ["EM-11"]}))
        h.record_gateway_error("CGW-2", json.dumps({"error_type": "GATEWAY_ATTACHMENT_ERROR", "device_id": "EM-11", "description": "not bound"}))
        status = _state(h, "CGW-2")["gateway"]["status"]
        assert status["category"] == CATEGORY_GATEWAY_SETUP_ATTACH
        assert "EM-11" in status["message"]
        h.handle_config("EM-11", _em11_config())
        assert "status" not in _state(h, "CGW-2")["gateway"]


class TestStatePublishing:
    def test_failed_publish_is_retried_and_reconnect_forces_state(self, handler_factory):
        h = handler_factory()
        h.handle_config("CGW-2", _config("2026-11-04T10:00:00Z"))
        now = time.monotonic()
        assert h.pop_due_state_payload("CGW-2", now_mono=now) is not None
        assert h.pop_due_state_payload("CGW-2", now_mono=now + 5) is None
        h.state_publish_failed("CGW-2")
        assert h.pop_due_state_payload("CGW-2", now_mono=now + 10) is not None
        h.force_republish_all()
        assert h.pop_due_state_payload("CGW-2", now_mono=now + 11) is None  # throttled
        assert h.pop_due_state_payload("CGW-2", now_mono=now + 14) is not None

    def test_reverted_change_is_not_republished(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-11", _em11_config())
        now = time.monotonic()
        h.record_modbus_payload(_frame({3028: 230.0, 3110: 50.0}, qty=84), now_mono=now)
        assert h.pop_due_state_payload("EM-11", now_mono=now) is not None
        h.handle_config("EM-11", _em11_config(target={"family": "bacnet"}))
        h.handle_config("EM-11", _em11_config())
        assert h.pop_due_state_payload("EM-11", now_mono=now + 5) is None

    def test_pending_logs_are_bounded(self, handler_factory):
        h = handler_factory()
        for i in range(500):
            h.handle_config("EM-11", _config(f"2026-11-04T10:{i // 60:02d}:{i % 60:02d}Z"))
        assert len(h.devices_by_id["EM-11"]["pending_logs"]) <= module.MAX_PENDING_LOGS


class TestEnumeration:
    def test_enumeration_reports_device_knowledge(self, handler_factory):
        h = handler_factory()
        h.handle_config(
            "EM-11",
            _config(
                "2026-11-04T10:00:00Z",
                discovery={"generation": "2026-11-04T10:00:00Z",
                           "enumerations": {"families": "details", "features": "details", "points": "details"}},
            ),
        )
        events = [json.loads(e) for e in h.pop_due_discovery_events("EM-11")]
        assert len(events) == 1
        event = events[0]
        assert event["features"] == PROXY_FEATURES
        assert event["families"] == {"modbus": {"addr": "ttyM0"}}
        assert len(event["points"]) == 42  # every point in the PM5561 register map
        assert event["points"]["line1_neutral_voltage_sensor"]["ref"] == "3/3028/2?type=FLOAT32"

        h.handle_config(
            "CGW-2",
            _config("2026-11-04T10:00:00Z", discovery={"generation": "g1", "enumerations": {"features": "entries"}}),
        )
        assert json.loads(h.pop_due_discovery_events("CGW-2")[0])["features"] == GATEWAY_FEATURES

    def test_unsupported_blobs_are_reported(self, handler_factory):
        h = handler_factory()
        h.handle_config("CGW-2", _config("2026-11-04T10:00:00Z", blobset={"blobs": {"_firmware_update": {"generation": "2026-11-04T09:00:00Z"}}}))
        blob = _state(h, "CGW-2")["blobset"]["blobs"]["_firmware_update"]
        assert blob["phase"] == "final"
        assert blob["status"]["level"] == LEVEL_ERROR

    def test_unsupported_alarms_carry_a_status_each(self, handler_factory):
        h = handler_factory()
        h.handle_config("EM-11", _config("2026-11-04T10:00:00Z", alarmset={"alarms": {"over_voltage": {}}}))
        alarm = _state(h, "EM-11")["alarmset"]["alarms"]["over_voltage"]
        assert alarm["value_state"] == "invalid"
        assert alarm["status"]["category"] == CATEGORY_SYSTEM_CONFIG_APPLY
        assert alarm["status"]["level"] == LEVEL_ERROR
        assert "over_voltage" in alarm["status"]["message"]
