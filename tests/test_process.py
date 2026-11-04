# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Process-level behaviour that needs no MQTT broker: exit codes of both entry points."""

import importlib.util
import subprocess
import sys

import pytest

from conftest import REPO_ROOT
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
