import json
import logging
import math
import os
import queue
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from google_iot_core_gateway import UDMI_VERSION
from google_iot_core_gateway.gcp_handler import (
    process_downlink_configs,
    process_payloads,
    publish_due_udmi_messages,
)
from google_iot_core_gateway.gcp_publisher import GoogleIoTCoreMQTTPublisher
from google_iot_core_gateway.internal_broker_subscriber.internal_broker_subscriber import (
    MosquittoMQTTSubscriber,
)
from google_iot_core_gateway.modbus_gw.modbus_to_json import (
    append_modbus_crc16,
    modbus_to_json,
    verify_modbus_crc16,
)
from google_iot_core_gateway.udmi_handler.udmi_handler import (
    CATEGORY_GATEWAY_PROXY_TARGET,
    CATEGORY_POINTSET_POINT_FAILURE,
    CATEGORY_POINTSET_POINT_INVALID,
    CATEGORY_SYSTEM_CONFIG_APPLY,
    CATEGORY_SYSTEM_CONFIG_PARSE,
    CATEGORY_SYSTEM_CONFIG_RECEIVE,
    LEVEL_DEBUG,
    LEVEL_ERROR,
    LEVEL_INFO,
    LEVEL_NOTICE,
    LEVEL_WARNING,
    UDMIHandler,
)

RESOURCES_DIR = str(REPO_ROOT / "resources")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _create_cgw2_site_model(base_dir: Path) -> Path:
    site_dir = base_dir / "site_model"
    (site_dir / "devices" / "CGW-2").mkdir(parents=True)
    (site_dir / "devices" / "EM-11").mkdir(parents=True)

    (site_dir / "cloud_iot_config.json").write_text(
        json.dumps(
            {
                "cloud_region": "europe-west1",
                "site_name": "UK-LON-GLAB",
                "registry_id": "UK-LON-GLAB",
            }
        ),
        encoding="utf-8",
    )

    cgw2_meta = {
        "version": "1.5.2",
        "timestamp": "2024-09-23T10:46:31Z",
        "system": {
            "hardware": {"make": "Moxa", "model": "UC8220"},
            "software": {"firmware": "4.2.0"},
            "serial_no": "CGW2-SN-999",
        },
        "gateway": {"proxy_ids": ["EM-11"]},
        "pointset": {"points": {}},
        "localnet": {
            "families": {
                "ether": {"addr": "00:90:e8:11:22:33"},
                "ipv4": {"addr": "192.168.10.2"},
            }
        },
    }
    (site_dir / "devices" / "CGW-2" / "metadata.json").write_text(
        json.dumps(cgw2_meta), encoding="utf-8"
    )

    em11_meta = {
        "version": "1.5.2",
        "timestamp": "2024-09-23T10:46:31Z",
        "system": {
            "hardware": {"make": "Schneider Electric", "model": "PM5111"},
            "software": {"firmware": "1.4.2"},
        },
        "gateway": {
            "gateway_id": "CGW-2",
            "target": {"family": "modbus", "addr": "1"},
        },
        "pointset": {
            "points": {
                "line1_neutral_voltage_sensor": {"units": "Volts", "ref": "3028"},
                "frequency_sensor": {"units": "Hertz", "ref": "3110"},
            }
        },
    }
    (site_dir / "devices" / "EM-11" / "metadata.json").write_text(
        json.dumps(em11_meta), encoding="utf-8"
    )
    return site_dir


class TestModbusToJson:
    def test_crc16_and_pm5111_float32_and_nan_filtering(self):
        # Request 2 registers starting at 0-based PDU 3027 (1-based reg 3028: line1_neutral_voltage_sensor)
        req = append_modbus_crc16(struct.pack(">BBHH", 1, 3, 3027, 2))
        resp = append_modbus_crc16(struct.pack(">BBB", 1, 3, 4) + struct.pack(">f", 230.5))
        assert verify_modbus_crc16(req)
        assert verify_modbus_crc16(resp)

        decoded = json.loads(
            modbus_to_json(req, resp, slave_to_type={1: "PM5111"}, strict_crc=True)
        )
        assert decoded["error"] is None
        assert decoded["data"]["3028"] == pytest.approx(230.5)

        # NaN float must be omitted rather than serialized as "N/A(...)" string
        nan_resp = append_modbus_crc16(
            struct.pack(">BBB", 1, 3, 4) + struct.pack(">f", float("nan"))
        )
        nan_decoded = json.loads(
            modbus_to_json(req, nan_resp, slave_to_type={1: "PM5111"}, strict_crc=True)
        )
        assert nan_decoded["error"] is None
        assert "3028" not in nan_decoded["data"]

    def test_crc_mismatch_and_modbus_exception_frame(self):
        req = append_modbus_crc16(struct.pack(">BBHH", 1, 3, 2999, 2))
        bad_crc_resp = struct.pack(">BBB", 1, 3, 4) + struct.pack(">f", 12.0) + b"\xde\xad"
        decoded_bad = json.loads(modbus_to_json(req, bad_crc_resp, slave_to_type={1: "PM5111"}))
        assert "CRC" in decoded_bad["error"]

        # Exception response FC 0x83, Illegal Data Address (0x02)
        exc_resp = append_modbus_crc16(struct.pack(">BBB", 1, 0x83, 0x02))
        decoded_exc = json.loads(modbus_to_json(req, exc_resp, slave_to_type={1: "PM5111"}))
        assert decoded_exc["error"] == "Modbus exception code 0x02"

    def test_odd_int16u_and_pm8240_odd_str40_registers(self):
        # Register 1637 (int16u firmware_version on PM5111, 0-based PDU 1636, qty 1)
        req_fw = append_modbus_crc16(struct.pack(">BBHH", 1, 3, 1636, 1))
        resp_fw = append_modbus_crc16(struct.pack(">BBBH", 1, 3, 2, 104))
        decoded_fw = json.loads(modbus_to_json(req_fw, resp_fw, slave_to_type={1: "PM5111"}))
        assert decoded_fw["data"]["1637"] == 104

        # Register 117 (str40 12-register serial_no on PM8240, 0-based PDU 116, qty 12)
        raw_str = b"SN-PM8240-7788".ljust(24, b"\x00")
        req_sn = append_modbus_crc16(struct.pack(">BBHH", 3, 3, 116, 12))
        resp_sn = append_modbus_crc16(struct.pack(">BBB", 3, 3, 24) + raw_str)
        decoded_sn = json.loads(modbus_to_json(req_sn, resp_sn, slave_to_type={3: "PM8240"}))
        assert decoded_sn["data"]["117"] == "SN-PM8240-7788"


class TestUDMIHandlerSequencerCompliance:
    def _make_handler(self, tmp_path: Path) -> UDMIHandler:
        site_dir = _create_cgw2_site_model(tmp_path)
        logger = logging.getLogger("test_udmi")
        handler = UDMIHandler(
            logger,
            RESOURCES_DIR,
            str(site_dir),
            default_sample_rate_sec=10.0,
            config_wait_timeout_sec=0.0,
        )
        assert handler.add_device_to_dict(1, "EM-11", "PM5111")
        assert handler.register_gateway("CGW-2", proxy_ids=["EM-11"])
        # Flush initial system.base.ready logs so test assertions start from a clean slate
        handler.pop_due_system_event_payload("CGW-2")
        handler.pop_due_system_event_payload("EM-11")
        return handler

    def test_broken_config_and_reset_logging_sequence(self, tmp_path: Path):
        handler = self._make_handler(tmp_path)

        # 1. Enable DEBUG logging via valid config
        stable_ts = "2026-10-30T10:00:00Z"
        assert handler.handle_config(
            "CGW-2",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": stable_ts,
                    "system": {"min_loglevel": LEVEL_DEBUG},
                    "gateway": {"proxy_ids": ["EM-11"]},
                    "pointset": {"points": {}},
                }
            ),
        )
        ev1 = json.loads(handler.pop_due_system_event_payload("CGW-2"))
        cats1 = [e["category"] for e in ev1["logentries"]]
        # Receive/parse were evaluated at prior INFO level (suppressed), apply logged at NOTICE
        assert cats1 == [CATEGORY_SYSTEM_CONFIG_APPLY]
        st1 = json.loads(handler.get_state_payload("CGW-2"))
        assert st1["system"]["last_config"] == stable_ts
        assert "status" not in st1["system"]

        # 2. Send broken (non-JSON) config: must log receive(100) + parse(500), NO apply,
        # set system.status=500 system.config.parse, and preserve last_config == stable_ts!
        assert not handler.handle_config("CGW-2", "{ invalid broken json !!!")
        ev2 = json.loads(handler.pop_due_system_event_payload("CGW-2"))
        entries2 = [(e["category"], e["level"]) for e in ev2["logentries"]]
        assert (CATEGORY_SYSTEM_CONFIG_RECEIVE, LEVEL_DEBUG) in entries2
        assert (CATEGORY_SYSTEM_CONFIG_PARSE, LEVEL_ERROR) in entries2
        assert all(cat != CATEGORY_SYSTEM_CONFIG_APPLY for cat, _ in entries2)

        st2 = json.loads(handler.get_state_payload("CGW-2"))
        assert st2["system"]["last_config"] == stable_ts
        assert st2["system"]["status"]["category"] == CATEGORY_SYSTEM_CONFIG_PARSE
        assert st2["system"]["status"]["level"] == LEVEL_ERROR

        # 3. Sequencer resetConfig(): full reset sets min_loglevel=INFO, then soft reset arrives
        handler.handle_config(
            "CGW-2",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T10:00:05Z",
                    "system": {"min_loglevel": LEVEL_INFO, "extra_field": "reset_config"},
                }
            ),
        )
        handler.pop_due_system_event_payload("CGW-2")

        soft_reset_ts = "2026-10-30T10:00:06Z"
        assert handler.handle_config(
            "CGW-2",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": soft_reset_ts,
                    "system": {"min_loglevel": LEVEL_INFO},
                    "gateway": {"proxy_ids": ["EM-11"]},
                    "pointset": {"points": {}},
                }
            ),
        )
        ev3 = json.loads(handler.pop_due_system_event_payload("CGW-2"))
        cats3 = [e["category"] for e in ev3["logentries"]]
        # Receive & parse must NOT be logged since min_loglevel was INFO before apply
        assert cats3 == [CATEGORY_SYSTEM_CONFIG_APPLY]
        st3 = json.loads(handler.get_state_payload("CGW-2"))
        assert st3["system"]["last_config"] == soft_reset_ts
        assert "status" not in st3["system"]

    def test_extra_config_min_loglevel_subblock_parity_and_localnet(self, tmp_path: Path):
        handler = self._make_handler(tmp_path)

        # Config with localnet + extra unknown field at WARNING level -> apply(300) suppressed!
        cfg_warn = {
            "version": UDMI_VERSION,
            "timestamp": "2026-10-30T10:05:00Z",
            "system": {
                "min_loglevel": LEVEL_WARNING,
                "extra_field": "Flabberguilstadt",
            },
            "localnet": {"families": {"ether": {}, "ipv4": {}}},
        }
        assert handler.handle_config("CGW-2", json.dumps(cfg_warn))
        assert handler.pop_due_system_event_payload("CGW-2") is None

        state = json.loads(handler.get_state_payload("CGW-2"))
        # Subblock parity: gateway and pointset were omitted in cfg_warn, localnet was present!
        assert set(state.keys()) == {"version", "timestamp", "system", "localnet"}
        ether_addr = state["localnet"]["families"]["ether"]["addr"]
        assert len(ether_addr.split(":")) == 6 and ether_addr == ether_addr.lower()
        assert state["localnet"]["families"]["ipv4"]["addr"]
        assert state["system"]["hardware"] == {"make": "Moxa", "model": "UC8220"}
        assert state["system"]["software"] == {"firmware": "4.2.0"}
        assert state["system"]["serial_no"] == "CGW2-SN-999"

        # State throttle & dirty tracking: calling pop_due_state_payload again returns None
        assert handler.pop_due_state_payload("CGW-2") is None

    def test_pointset_gateway_and_proxied_sequences(self, tmp_path: Path):
        handler = self._make_handler(tmp_path)

        # Feed valid numeric readings to EM-11
        handler.update_device_properties(1, "PM5111", 3028, 231.25)
        handler.update_device_properties(1, "PM5111", 3110, 50.01)

        # CGW-2 empty pointset + extraneous point test
        handler.handle_config(
            "CGW-2",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T10:10:00Z",
                    "system": {"min_loglevel": LEVEL_INFO},
                    "gateway": {"proxy_ids": ["EM-11"]},
                    "pointset": {
                        "sample_limit_sec": 5,
                        "sample_rate_sec": 8,
                        "points": {"extraneous_point": {}},
                    },
                }
            ),
        )
        gw_state = json.loads(handler.get_state_payload("CGW-2"))
        ext_status = gw_state["pointset"]["points"]["extraneous_point"]["status"]
        assert ext_status["category"] == CATEGORY_POINTSET_POINT_INVALID
        assert ext_status["level"] == LEVEL_ERROR

        gw_event = json.loads(handler.get_event_point_payload("CGW-2"))
        assert gw_event["points"] == {}
        assert handler.devices_by_id["CGW-2"]["sample_interval_sec"] == pytest.approx(6.5)

        # EM-11 point removal + bad_point_ref + bad_target_family + bad_target_address
        handler.handle_config(
            "EM-11",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T10:10:01Z",
                    "system": {"min_loglevel": LEVEL_INFO},
                    "gateway": {"target": {"family": "family-dead", "addr": "1"}},
                    "pointset": {
                        "sample_rate_sec": 10,
                        "points": {
                            "line1_neutral_voltage_sensor": {"units": "Volts", "ref": "3028"}
                        },
                    },
                }
            ),
        )
        em_state = json.loads(handler.get_state_payload("EM-11"))
        # frequency_sensor was removed from config -> must be absent from state & events!
        assert list(em_state["pointset"]["points"].keys()) == ["line1_neutral_voltage_sensor"]
        assert em_state["pointset"]["points"]["line1_neutral_voltage_sensor"] == {}
        assert em_state["gateway"]["status"]["category"] == CATEGORY_GATEWAY_PROXY_TARGET
        assert em_state["gateway"]["status"]["level"] == LEVEL_ERROR

        em_event = json.loads(handler.get_event_point_payload("EM-11"))
        assert em_event["points"] == {
            "line1_neutral_voltage_sensor": {"present_value": 231.25}
        }

        # Restore target family, break point ref -> gateway status clears, point status reports failure
        handler.handle_config(
            "EM-11",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T10:10:02Z",
                    "system": {"min_loglevel": LEVEL_INFO},
                    "gateway": {"target": {"family": "modbus", "addr": "1"}},
                    "pointset": {
                        "sample_rate_sec": 10,
                        "points": {
                            "line1_neutral_voltage_sensor": {
                                "units": "Volts",
                                "ref": "ref-bad999",
                            }
                        },
                    },
                }
            ),
        )
        em_state2 = json.loads(handler.get_state_payload("EM-11"))
        assert em_state2["gateway"] == {}
        pt_err = em_state2["pointset"]["points"]["line1_neutral_voltage_sensor"]["status"]
        assert pt_err["category"] == CATEGORY_POINTSET_POINT_FAILURE
        assert pt_err["level"] == LEVEL_ERROR
        assert json.loads(handler.get_event_point_payload("EM-11"))["points"] == {}

    def test_udmi_1_5_canonical_modbus_refs_and_proxied_localnet_isolation(self, tmp_path: Path):
        site_dir = _create_cgw2_site_model(tmp_path)
        # Configure EM-11 with UDMI 1.5 ModbusFamilyProvider canonical refs and localnet.families.modbus
        em11_meta = {
            "version": UDMI_VERSION,
            "timestamp": "2024-09-23T10:46:31Z",
            "system": {
                "hardware": {"make": "Schneider Electric", "model": "PM5561"},
                "software": {"firmware": "1.4.0"},
                "serial_no": "EM-11-SN-001",
            },
            "gateway": {"gateway_id": "CGW-2", "target": {"family": "modbus"}},
            "localnet": {"families": {"modbus": {"addr": "ttyM0", "unitid": "1"}}},
            "pointset": {
                "points": {
                    "line1_neutral_voltage_sensor": {
                        "units": "Volts",
                        "ref": "3/3028/2?type=FLOAT32",
                    },
                    "frequency_sensor": {
                        "units": "Hertz",
                        "ref": "modbus://ttyM0/1/3/3110/2?type=FLOAT32",
                    },
                }
            },
        }
        (site_dir / "devices" / "EM-11" / "metadata.json").write_text(
            json.dumps(em11_meta), encoding="utf-8"
        )

        logger = logging.getLogger("test_canonical_modbus")
        handler = UDMIHandler(
            logger,
            RESOURCES_DIR,
            str(site_dir),
            default_sample_rate_sec=10.0,
            config_wait_timeout_sec=0.0,
        )
        assert handler.add_device_to_dict(1, "EM-11", "PM5561", serial_no="EM-11-SN-001")
        assert handler.register_gateway("CGW-2", proxy_ids=["EM-11"], serial_no="CGW2-UC8220-001")
        handler.update_device_properties(1, "PM5561", 3028, 230.75)
        handler.update_device_properties(1, "PM5561", 3110, 50.00)

        # ApplyRegistrar-synthesized config (target.addr="ttyM0", localnet.families.modbus={}, canonical refs)
        assert handler.handle_config(
            "EM-11",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T12:00:00Z",
                    "system": {"min_loglevel": LEVEL_INFO},
                    "gateway": {"target": {"family": "modbus", "addr": "ttyM0"}},
                    "localnet": {"families": {"modbus": {}}},
                    "pointset": {
                        "sample_rate_sec": 10,
                        "points": {
                            "line1_neutral_voltage_sensor": {
                                "units": "Volts",
                                "ref": "3/3028/2?type=FLOAT32",
                            },
                            "frequency_sensor": {
                                "units": "Hertz",
                                "ref": "modbus://ttyM0/1/3/3110/2?type=FLOAT32",
                            },
                        },
                    },
                }
            ),
        )
        st = json.loads(handler.get_state_payload("EM-11"))
        # Must NOT leak unitid (disallowed by state_localnet_family.json) or host ether/ipv4 NICs!
        assert st["localnet"] == {"families": {"modbus": {"addr": "ttyM0"}}}
        assert st["gateway"] == {}
        assert st["pointset"]["points"] == {
            "line1_neutral_voltage_sensor": {},
            "frequency_sensor": {},
        }
        ev = json.loads(handler.get_event_point_payload("EM-11"))
        assert ev["points"] == {
            "line1_neutral_voltage_sensor": {"present_value": 230.75},
            "frequency_sensor": {"present_value": 50.0},
        }

    def test_system_mode_restart_and_self_enumeration(self, tmp_path: Path):
        site_dir = _create_cgw2_site_model(tmp_path)
        em11_meta = json.loads(
            (site_dir / "devices" / "EM-11" / "metadata.json").read_text(encoding="utf-8")
        )
        em11_meta["localnet"] = {"families": {"modbus": {"addr": "ttyM0", "unitid": "1"}}}
        (site_dir / "devices" / "EM-11" / "metadata.json").write_text(
            json.dumps(em11_meta), encoding="utf-8"
        )
        logger = logging.getLogger("test_restart_and_enum")
        handler = UDMIHandler(
            logger,
            RESOURCES_DIR,
            str(site_dir),
            default_sample_rate_sec=10.0,
            config_wait_timeout_sec=0.0,
        )
        assert handler.add_device_to_dict(1, "EM-11", "PM5561", serial_no="EM-11-SN-001")
        assert handler.register_gateway("CGW-2", proxy_ids=["EM-11"], serial_no="CGW2-UC8220-001")

        # 1. Verify initial restart_count >= 1 and mode == "active"
        st0 = json.loads(handler.get_state_payload("CGW-2"))
        assert st0["system"]["operation"]["restart_count"] == 1
        assert st0["system"]["operation"]["mode"] == "active"
        prev_start = st0["system"]["operation"]["last_start"]

        # 2. Trigger system_mode_restart -> mode transitions to "initial", restart_count == 2, newer last_start
        assert handler.handle_config(
            "CGW-2",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T13:00:00Z",
                    "system": {"operation": {"mode": "restart", "last_start": prev_start}},
                }
            ),
        )
        st1 = json.loads(handler.get_state_payload("CGW-2"))
        assert st1["system"]["operation"]["mode"] == "initial"
        assert st1["system"]["operation"]["restart_count"] == 2
        assert st1["system"]["operation"]["last_start"] > prev_start

        # Duplicate config while still in "restart" must NOT double-increment restart_count
        assert handler.handle_config(
            "CGW-2",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T13:00:01Z",
                    "system": {
                        "operation": {
                            "mode": "restart",
                            "last_start": st1["system"]["operation"]["last_start"],
                        }
                    },
                }
            ),
        )
        st2 = json.loads(handler.get_state_payload("CGW-2"))
        assert st2["system"]["operation"]["restart_count"] == 2
        assert st2["system"]["operation"]["mode"] == "initial"

        # Sequencer transitions mode back to "active"
        assert handler.handle_config(
            "CGW-2",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T13:00:02Z",
                    "system": {
                        "operation": {
                            "mode": "active",
                            "last_start": st1["system"]["operation"]["last_start"],
                        }
                    },
                }
            ),
        )
        st3 = json.loads(handler.get_state_payload("CGW-2"))
        assert st3["system"]["operation"]["mode"] == "active"
        assert st3["system"]["operation"]["restart_count"] == 2

        # 3. Verify enumerate_nothing and enumerate_multi on EM-11
        gen_ts = "2026-10-30T13:05:00Z"
        assert handler.handle_config(
            "EM-11",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T13:05:01Z",
                    "system": {"min_loglevel": LEVEL_INFO},
                    "discovery": {"generation": gen_ts},
                }
            ),
        )
        em_st = json.loads(handler.get_state_payload("EM-11"))
        assert em_st["discovery"]["generation"] == gen_ts
        disc_events = [json.loads(x) for x in handler.pop_due_discovery_events("EM-11")]
        assert len(disc_events) == 1
        assert disc_events[0]["generation"] == gen_ts
        assert "families" not in disc_events[0]
        assert "features" not in disc_events[0]
        assert "points" not in disc_events[0]

        # Clear generation -> state.discovery omits generation; then trigger enumerate_multi
        assert handler.handle_config(
            "EM-11",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T13:05:02Z",
                    "system": {"min_loglevel": LEVEL_INFO},
                    "discovery": {},
                }
            ),
        )
        assert "generation" not in json.loads(handler.get_state_payload("EM-11"))["discovery"]

        gen_ts2 = "2026-10-30T13:06:00Z"
        assert handler.handle_config(
            "EM-11",
            json.dumps(
                {
                    "version": UDMI_VERSION,
                    "timestamp": "2026-10-30T13:06:01Z",
                    "system": {"min_loglevel": LEVEL_INFO},
                    "discovery": {
                        "generation": gen_ts2,
                        "enumerations": {
                            "families": "details",
                            "features": "details",
                            "points": "details",
                        },
                    },
                }
            ),
        )
        disc_multi = [json.loads(x) for x in handler.pop_due_discovery_events("EM-11")]
        assert len(disc_multi) == 1
        assert disc_multi[0]["generation"] == gen_ts2
        assert "modbus" in disc_multi[0]["families"]
        assert "enumeration" in disc_multi[0]["features"]
        assert "line1_neutral_voltage_sensor" in disc_multi[0]["points"]


class TestLiveMosquittoEndToEnd:
    def test_end_to_end_gateway_and_proxy_over_mosquitto(self, tmp_path: Path):
        if not os.path.exists("/usr/sbin/mosquitto"):
            pytest.skip("mosquitto binary not installed")

        port = _find_free_port()
        mosq_conf = tmp_path / "mosquitto.conf"
        mosq_conf.write_text(
            f"listener {port} 127.0.0.1\nallow_anonymous true\n", encoding="utf-8"
        )
        proc = subprocess.Popen(
            ["/usr/sbin/mosquitto", "-c", str(mosq_conf)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            time.sleep(0.4)
            site_dir = _create_cgw2_site_model(tmp_path)
            logger = logging.getLogger("e2e_test")

            handler = UDMIHandler(
                logger,
                RESOURCES_DIR,
                str(site_dir),
                default_sample_rate_sec=2.0,
                config_wait_timeout_sec=1.0,
            )
            handler.add_device_to_dict(1, "EM-11", "PM5111")
            handler.register_gateway("CGW-2", proxy_ids=["EM-11"])

            captured = queue.Queue()
            observer = (
                mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
                if hasattr(mqtt, "CallbackAPIVersion")
                else mqtt.Client()
            )
            observer.on_message = lambda _c, _u, msg: captured.put(
                (msg.topic, msg.payload.decode("utf-8"))
            )
            observer.connect("127.0.0.1", port, 60)
            observer.subscribe("/r/UK-LON-GLAB/d/#", qos=1)
            observer.loop_start()

            publisher = GoogleIoTCoreMQTTPublisher(
                logger=logger,
                connected_devices={"EM-11": {"type": "PM5111", "modbus_slave_id": 1}},
                project_id="local",
                cloud_region="europe-west1",
                registry_id="UK-LON-GLAB",
                gateway_id="CGW-2",
                private_key_file=None,
                ca_cert=None,
                mqtt_bridge_hostname="127.0.0.1",
                mqtt_bridge_port=port,
                iot_provider="mqtt",
                enable_tls=False,
            )
            assert publisher._maximum_backoff_time >= 120.0
            assert publisher._is_connected

            internal_q = queue.Queue(maxsize=100)
            sub = MosquittoMQTTSubscriber(
                logger, internal_q, host="127.0.0.1", port=port, enable_tls=False
            )
            sub.run()
            time.sleep(0.3)

            # Publish a synthetic MXcloudgate Modbus RTU frame for slave 1 reg 3028 = 240.0V
            req = append_modbus_crc16(struct.pack(">BBHH", 1, 3, 3027, 2))
            resp = append_modbus_crc16(
                struct.pack(">BBB", 1, 3, 4) + struct.pack(">f", 240.0)
            )
            observer.publish(
                "MXcloudgate",
                json.dumps({"rtu_request": req.hex(), "rtu_response": resp.hex()}),
                qos=0,
            )

            # Send downlink configs to CGW-2 and EM-11
            cfg_ts = "2026-10-30T11:00:00Z"
            observer.publish(
                "/r/UK-LON-GLAB/d/CGW-2/config",
                json.dumps(
                    {
                        "version": UDMI_VERSION,
                        "timestamp": cfg_ts,
                        "system": {"min_loglevel": LEVEL_INFO},
                        "gateway": {"proxy_ids": ["EM-11"]},
                        "pointset": {"sample_rate_sec": 1, "points": {}},
                    }
                ),
                qos=1,
            )
            observer.publish(
                "/r/UK-LON-GLAB/d/EM-11/config",
                json.dumps(
                    {
                        "version": UDMI_VERSION,
                        "timestamp": cfg_ts,
                        "system": {"min_loglevel": LEVEL_INFO},
                        "gateway": {},
                        "pointset": {
                            "sample_rate_sec": 1,
                            "points": {"line1_neutral_voltage_sensor": {"units": "Volts"}},
                        },
                    }
                ),
                qos=1,
            )

            deadline = time.time() + 4.0
            seen_topics = {}
            while time.time() < deadline:
                process_downlink_configs(logger, publisher, handler)
                process_payloads(logger, internal_q, handler)
                publish_due_udmi_messages(logger, publisher, handler)
                while not captured.empty():
                    t, p = captured.get_nowait()
                    seen_topics[t] = p
                if (
                    "/r/UK-LON-GLAB/d/CGW-2/state" in seen_topics
                    and "/r/UK-LON-GLAB/d/EM-11/state" in seen_topics
                    and "/r/UK-LON-GLAB/d/CGW-2/events/pointset" in seen_topics
                    and "/r/UK-LON-GLAB/d/EM-11/events/pointset" in seen_topics
                ):
                    break
                time.sleep(0.1)

            assert "/r/UK-LON-GLAB/d/EM-11/attach" in seen_topics
            assert (
                json.loads(seen_topics["/r/UK-LON-GLAB/d/CGW-2/state"])["system"]["last_config"]
                == cfg_ts
            )
            em_ps = json.loads(seen_topics["/r/UK-LON-GLAB/d/EM-11/events/pointset"])
            assert em_ps["points"]["line1_neutral_voltage_sensor"]["present_value"] == pytest.approx(
                240.0
            )

            sub.stop()
            publisher.close()
            observer.loop_stop()
            observer.disconnect()
        finally:
            proc.terminate()
            proc.wait(timeout=5)
