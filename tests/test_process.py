# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Process-level behaviour that needs no MQTT broker: exit codes and signals of both entry points."""

import importlib.util
import json
import signal
import subprocess
import sys
import time

import pytest

from conftest import REPO_ROOT, RESOURCES_DIR, find_free_port, write_site_model
from google_iot_core_gateway.errors import EXIT_FATAL, EXIT_OK, EXIT_RESTART


def test_main_exits_non_zero_on_fatal_configuration_errors(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-B", str(REPO_ROOT / "src" / "main.py"), "-c", str(tmp_path / "missing.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False,
    )
    assert proc.returncode == EXIT_FATAL


def test_module_entry_point_propagates_the_exit_code(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "google_iot_core_gateway",
         "-google-cloud-config-file", str(tmp_path / "missing.json")],
        cwd=str(REPO_ROOT / "src"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False,
    )
    assert proc.returncode == EXIT_FATAL


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT], ids=["SIGTERM", "SIGINT"])
def test_module_entry_point_stops_cleanly_on_signals(tmp_path, signum):
    """`systemctl stop` (SIGTERM) or Ctrl-C must end `python -m` with exit 0, not kill it mid-flight."""
    site_dir = write_site_model(tmp_path)
    state_dir = tmp_path / "state"
    unreachable = find_free_port()  # nothing listens here: both brokers stay unreachable
    config = tmp_path / "gateway-config.json"
    config.write_text(json.dumps({
        "internal_broker": {"mqtt_bridge_hostname": "127.0.0.1", "mqtt_bridge_port": unreachable},
        "google_cloud": {"iot_provider": "mqtt", "mqtt_bridge_hostname": "127.0.0.1",
                         "mqtt_bridge_port": unreachable, "enable_tls": False},
        "site_details": {"gateway_id": "CGW-2", "serial_no": "CGW2-SIGNALS",
                         "hardware": {"make": "Moxa", "model": "UC8220"},
                         "proxy_ids": {"EM-11": {"type": "PM5561", "modbus_slave_id": 1, "port": "ttyM0"}}},
        "environment_setup": {"udmi_site_model_path": str(site_dir), "resources_path": RESOURCES_DIR,
                              "state_dir": str(state_dir)},
    }), encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-B", "-m", "google_iot_core_gateway", "-google-cloud-config-file", str(config)],
        cwd=str(REPO_ROOT / "src"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        # The restart counter is persisted after the signal handlers are installed.
        started = state_dir / "persistent_data.json"
        deadline = time.monotonic() + 30
        while not started.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert started.exists(), f"gateway did not start (exit code {proc.poll()})"
        proc.send_signal(signum)
        assert proc.wait(timeout=20) == EXIT_OK
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def _load_main_module():
    spec = importlib.util.spec_from_file_location("moxa_gateway_main", REPO_ROOT / "src" / "main.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _crash(*_args):
    raise RuntimeError("unexpected bug in the gateway thread")


def _exit_with(code):
    def _run(*_args):
        raise SystemExit(code)
    return _run


@pytest.mark.parametrize(
    "gateway, expected",
    [
        pytest.param(lambda *_args: EXIT_OK, EXIT_OK, id="clean-shutdown"),
        pytest.param(lambda *_args: EXIT_RESTART, EXIT_RESTART, id="udmi-restart"),
        pytest.param(_crash, EXIT_FATAL, id="unexpected-crash"),
        pytest.param(_exit_with(3), 3, id="system-exit-code"),
        pytest.param(_exit_with("message"), EXIT_FATAL, id="system-exit-message"),
    ],
)
def test_main_maps_gateway_thread_outcomes_to_exit_codes(monkeypatch, gateway, expected):
    """A crash in the worker thread must reach the supervisor as a failure, never as exit 0."""
    main_module = _load_main_module()
    monkeypatch.setattr(main_module.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(main_module, "start_google_iot_core_gateway", gateway)
    assert main_module.main(["-c", "unused.json"]) == expected
