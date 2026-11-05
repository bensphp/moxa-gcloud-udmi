# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Process-level behaviour that needs no MQTT broker: exit codes and signals of both entry points."""

import importlib.util
import json
import signal
import subprocess
import sys
import threading
import time

import pytest

from conftest import REPO_ROOT, RESOURCES_DIR, find_free_port, write_site_model
from google_iot_core_gateway import gcp_handler
from google_iot_core_gateway.errors import EXIT_FATAL, EXIT_OK, EXIT_RESTART

STOP_SIGNALS = {signal.SIGINT, signal.SIGTERM}
needs_sigmask = pytest.mark.skipif(not hasattr(signal, "pthread_sigmask"), reason="POSIX signal masks only")


def _blocked_signals():
    return set(signal.pthread_sigmask(signal.SIG_BLOCK, []))


def _write_unreachable_config(tmp_path):
    """Valid gateway configuration whose brokers do not exist (nothing listens on the port)."""
    site_dir = write_site_model(tmp_path)
    unreachable = find_free_port()
    config = tmp_path / "gateway-config.json"
    config.write_text(json.dumps({
        "internal_broker": {"mqtt_bridge_hostname": "127.0.0.1", "mqtt_bridge_port": unreachable},
        "google_cloud": {"iot_provider": "mqtt", "mqtt_bridge_hostname": "127.0.0.1",
                         "mqtt_bridge_port": unreachable, "enable_tls": False},
        "site_details": {"gateway_id": "CGW-2", "serial_no": "CGW2-SIGNALS",
                         "hardware": {"make": "Moxa", "model": "UC8220"},
                         "proxy_ids": {"EM-11": {"type": "PM5561", "modbus_slave_id": 1, "port": "ttyM0"}}},
        "environment_setup": {"udmi_site_model_path": str(site_dir), "resources_path": RESOURCES_DIR,
                              "state_dir": str(tmp_path / "state")},
    }), encoding="utf-8")
    return config


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
    """`systemctl stop` (SIGTERM) or Ctrl-C must end `python -m` with exit 0, also during start-up."""
    config = _write_unreachable_config(tmp_path)
    proc = subprocess.Popen(
        [sys.executable, "-B", "-m", "google_iot_core_gateway", "-google-cloud-config-file", str(config)],
        cwd=str(REPO_ROOT / "src"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        # The restart counter is persisted after the signal handlers are installed but before the
        # MQTT clients start, so the signal may arrive in the middle of the start-up.
        started = tmp_path / "state" / "persistent_data.json"
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


@needs_sigmask
def test_module_entry_point_runs_the_gateway_off_the_signal_thread(monkeypatch, logger):
    """`python -m`: the gateway (and the threads it starts) never receives SIGINT/SIGTERM."""
    monkeypatch.setattr(signal, "signal", lambda *_args: None)
    seen = {}

    def gateway(*_args, **_kwargs):
        seen["mask"] = _blocked_signals()
        seen["on_main_thread"] = threading.current_thread() is threading.main_thread()
        return EXIT_RESTART

    monkeypatch.setattr(gcp_handler, "start_google_iot_core_gateway", gateway)
    before = _blocked_signals()
    rc = gcp_handler.start_standalone_google_iot_core_gateway(["-google-cloud-config-file", "unused.json"], logger)
    assert rc == EXIT_RESTART
    assert STOP_SIGNALS <= seen["mask"]
    assert not seen["on_main_thread"]
    assert _blocked_signals() == before  # the main thread keeps handling them


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
    monkeypatch.setattr(signal, "signal", lambda *_args: None)
    monkeypatch.setattr(main_module, "start_google_iot_core_gateway", gateway)
    assert main_module.main(["-c", "unused.json"]) == expected


@needs_sigmask
def test_main_handles_stop_signals_on_the_main_thread_only(monkeypatch):
    """main.py's gateway thread (and the client threads it starts) must not receive stop signals."""
    main_module = _load_main_module()
    monkeypatch.setattr(signal, "signal", lambda *_args: None)
    seen = {}

    def gateway(*_args):
        seen["mask"] = _blocked_signals()
        return EXIT_OK

    monkeypatch.setattr(main_module, "start_google_iot_core_gateway", gateway)
    before = _blocked_signals()
    assert main_module.main(["-c", "unused.json"]) == EXIT_OK
    assert STOP_SIGNALS <= seen["mask"]
    assert _blocked_signals() == before  # the main thread keeps handling them
