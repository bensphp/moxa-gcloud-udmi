# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Shared test fixtures."""

import json
import logging
import shutil
import socket
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
TOOLS_DIR = REPO_ROOT / "tools"
TESTS_DIR = Path(__file__).resolve().parent
for _path in (SRC_DIR, TOOLS_DIR, TESTS_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

RESOURCES_DIR = str(REPO_ROOT / "resources")
UDMI_VERSION_FOR_TESTS = "1.5.2"
MOSQUITTO = shutil.which("mosquitto") or "/usr/sbin/mosquitto"

# Identity values that only exist in the fixture site model: the gateway must never report them.
META_GATEWAY_IDENTITY = {
    "hardware": {"make": "MetaMake", "model": "MetaModel"},
    "software": {"firmware": "0.0.1-meta"},
    "serial_no": "META-GW-SERIAL",
}
META_METER_IDENTITY = {
    "hardware": {"make": "MetaMeterMake", "model": "PM9999"},
    "software": {"firmware": "9.9-meta"},
    "serial_no": "META-EM-SERIAL",
}


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _meter_metadata(gateway_id, unit, points):
    return {
        "version": UDMI_VERSION_FOR_TESTS,
        "timestamp": "2024-09-23T10:46:31Z",
        "system": json.loads(json.dumps(META_METER_IDENTITY)),
        "gateway": {"gateway_id": gateway_id, "target": {"family": "modbus"}},
        "localnet": {"families": {"modbus": {"addr": "ttyM0", "unitid": str(unit)}}},
        "pointset": {"points": points},
    }


def write_site_model(base_dir: Path, em11_points=None, em11_localnet=None, cgw2_localnet=None, with_em12=False) -> Path:
    """Create a minimal CGW-2 + EM-11 (PM5561, unit 1 on ttyM0) [+ EM-12 (PM5111, unit 2)] site model."""
    site_dir = base_dir / "site_model"
    devices = ["CGW-2", "EM-11"] + (["EM-12"] if with_em12 else [])
    for device in devices:
        (site_dir / "devices" / device).mkdir(parents=True)
    (site_dir / "cloud_iot_config.json").write_text(
        json.dumps({"cloud_region": "europe-west1", "site_name": "UK-LON-GLAB", "registry_id": "UK-LON-GLAB"}),
        encoding="utf-8",
    )
    cgw2_meta = {
        "version": UDMI_VERSION_FOR_TESTS,
        "timestamp": "2024-09-23T10:46:31Z",
        "system": json.loads(json.dumps(META_GATEWAY_IDENTITY)),
        "gateway": {"proxy_ids": [d for d in devices if d != "CGW-2"]},
        "localnet": cgw2_localnet or {"families": {"ether": {"addr": "00:90:e8:11:22:33"}}},
    }
    (site_dir / "devices" / "CGW-2" / "metadata.json").write_text(json.dumps(cgw2_meta), encoding="utf-8")
    default_points = {
        "line1_neutral_voltage_sensor": {"units": "Volts", "ref": "3/3028/2?type=FLOAT32"},
        "frequency_sensor": {"units": "Hertz", "ref": "3/3110/2?type=FLOAT32"},
    }
    em11_meta = _meter_metadata("CGW-2", 1, em11_points or default_points)
    if em11_localnet:
        em11_meta["localnet"] = em11_localnet
    (site_dir / "devices" / "EM-11" / "metadata.json").write_text(json.dumps(em11_meta), encoding="utf-8")
    if with_em12:
        (site_dir / "devices" / "EM-12" / "metadata.json").write_text(
            json.dumps(_meter_metadata("CGW-2", 2, default_points)), encoding="utf-8"
        )
    return site_dir


@pytest.fixture
def logger():
    return logging.getLogger("moxa-tests")


@pytest.fixture
def site_dir(tmp_path):
    return write_site_model(tmp_path)


@pytest.fixture
def handler_factory(site_dir, logger, monkeypatch):
    """Build a UDMIHandler for CGW-2 + EM-11 with host detection stubbed out."""
    from google_iot_core_gateway.udmi_handler import udmi_handler as module

    monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
    monkeypatch.setattr(
        module,
        "_list_host_interfaces",
        lambda: ([{"ifname": "eth0", "ether": "00:90:e8:11:22:33", "ipv4": "192.168.4.2"}], True),
    )

    def _make(stale_timeout_sec=300.0, sample_rate=10.0, restart_count=1, port="ttyM0", site=None):
        handler = module.UDMIHandler(
            logger,
            RESOURCES_DIR,
            str(site or site_dir),
            default_sample_rate_sec=sample_rate,
            config_wait_timeout_sec=0.0,
            stale_timeout_sec=stale_timeout_sec,
        )
        assert handler.add_device_to_dict(1, "EM-11", "PM5561", port=port)
        assert handler.register_gateway(
            "CGW-2", proxy_ids=["EM-11"], serial_no="CGW2-CONFIGURED", restart_count=restart_count
        )
        handler.pop_due_system_event_payload("CGW-2")
        handler.pop_due_system_event_payload("EM-11")
        return handler

    return _make
