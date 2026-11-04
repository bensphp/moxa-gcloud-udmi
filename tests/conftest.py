# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Shared test fixtures."""

import json
import logging
import socket
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
TOOLS_DIR = REPO_ROOT / "tools"
for _path in (SRC_DIR, TOOLS_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

RESOURCES_DIR = str(REPO_ROOT / "resources")
UDMI_VERSION_FOR_TESTS = "1.5.2"


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_site_model(base_dir: Path, em11_points=None, em11_localnet=None, cgw2_localnet=None) -> Path:
    """Create a minimal CGW-2 + EM-11 (PM5561, unit 1 on ttyM0) site model."""
    site_dir = base_dir / "site_model"
    (site_dir / "devices" / "CGW-2").mkdir(parents=True)
    (site_dir / "devices" / "EM-11").mkdir(parents=True)
    (site_dir / "cloud_iot_config.json").write_text(
        json.dumps({"cloud_region": "europe-west1", "site_name": "UK-LON-GLAB", "registry_id": "UK-LON-GLAB"}),
        encoding="utf-8",
    )
    cgw2_meta = {
        "version": UDMI_VERSION_FOR_TESTS,
        "timestamp": "2024-09-23T10:46:31Z",
        "system": {"hardware": {"make": "Moxa", "model": "UC8220"}},
        "gateway": {"proxy_ids": ["EM-11"]},
        "localnet": cgw2_localnet or {"families": {"ether": {"addr": "00:90:e8:11:22:33"}}},
    }
    (site_dir / "devices" / "CGW-2" / "metadata.json").write_text(json.dumps(cgw2_meta), encoding="utf-8")
    em11_meta = {
        "version": UDMI_VERSION_FOR_TESTS,
        "timestamp": "2024-09-23T10:46:31Z",
        "system": {"hardware": {"make": "Schneider Electric", "model": "PM5561"}},
        "gateway": {"gateway_id": "CGW-2", "target": {"family": "modbus"}},
        "localnet": em11_localnet or {"families": {"modbus": {"addr": "ttyM0", "unitid": "1"}}},
        "pointset": {
            "points": em11_points
            or {
                "line1_neutral_voltage_sensor": {"units": "Volts", "ref": "3/3028/2?type=FLOAT32"},
                "frequency_sensor": {"units": "Hertz", "ref": "3/3110/2?type=FLOAT32"},
            }
        },
    }
    (site_dir / "devices" / "EM-11" / "metadata.json").write_text(json.dumps(em11_meta), encoding="utf-8")
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
