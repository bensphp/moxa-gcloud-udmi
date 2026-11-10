# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""tools/frame_report.py: pre-deployment report on MXcloudgate traffic (simulator frames)."""

import json
import struct

import pytest

import frame_report
import mxcloudgate_simulator as sim
from conftest import RESOURCES_DIR
from google_iot_core_gateway.modbus_gw.modbus_to_json import append_modbus_crc16


def _write_config(tmp_path, proxies=None):
    proxies = proxies or {
        "EM-1": {"type": "PM5561", "modbus_slave_id": 1},
        "EM-2": {"type": "PM5111", "modbus_slave_id": 2},
        "EM-3": {"type": "PM8240", "modbus_slave_id": 3},
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "site_details": {"gateway_id": "CGW-1", "proxy_ids": proxies},
        "environment_setup": {"resources_path": RESOURCES_DIR},
    }), encoding="utf-8")
    return str(path)


def _message(request, response):
    return json.dumps({"rtu_request": request.hex(), "rtu_response": response.hex()})


def _capture(tmp_path, frames, topic_prefix=True):
    """Write frames like `mosquitto_sub -v -t MXcloudgate` (or plain JSON lines)."""
    path = tmp_path / "frames.txt"
    lines = [("MXcloudgate " if topic_prefix else "") + _message(req, resp) for req, resp in frames]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def _block(request):
    """(first register (1-based), count) read by an FC03/FC04 request."""
    return int.from_bytes(request[2:4], "big") + 1, int.from_bytes(request[4:6], "big")


def _reads(request, register):
    first, count = _block(request)
    return first <= register < first + count


def _all_frames(slaves=(1, 2, 3)):
    return [frame for slave in slaves for frame in sim.build_slave_frames(slave, 1)]


def test_complete_valid_traffic_is_ready(tmp_path, capsys):
    rc = frame_report.main(["-c", _write_config(tmp_path), _capture(tmp_path, _all_frames())])
    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_READY, out
    assert "READY" in out
    assert "identity serial_no" in out and "52110001" in out  # EM-1's serial, decoded from the frames
    assert "sample" in out


def test_plain_json_lines_are_accepted(tmp_path):
    capture = _capture(tmp_path, _all_frames(), topic_prefix=False)
    assert frame_report.main(["-c", _write_config(tmp_path), capture]) == frame_report.EXIT_READY


def test_crc_failures_on_every_response_recommend_crc_check_off(tmp_path, capsys):
    frames = [(req, resp[:-2] + b"\x00\x00") for req, resp in _all_frames()]
    rc = frame_report.main(["-c", _write_config(tmp_path), _capture(tmp_path, frames)])
    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_PROBLEMS
    assert 'crc_check to "off"' in out


def test_some_crc_failures_point_at_the_wiring(tmp_path, capsys):
    frames = _all_frames()
    req, resp = frames[0]
    frames[0] = (req, resp[:-1] + bytes([resp[-1] ^ 0xFF]))
    rc = frame_report.main(["-c", _write_config(tmp_path), _capture(tmp_path, frames)])
    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_PROBLEMS
    assert "1 of" in out and "wiring" in out


def test_missing_identity_registers_are_reported(tmp_path, capsys):
    identity_regs = {130, 1637, 50, 70, 30}
    frames = [(req, resp) for req, resp in _all_frames() if not any(_reads(req, reg) for reg in identity_regs)]
    rc = frame_report.main(["-c", _write_config(tmp_path), _capture(tmp_path, frames)])
    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_PROBLEMS
    assert "identity registers not seen" in out and "serial_no (130)" in out


def test_meter_without_frames_and_unknown_unit_ids(tmp_path, capsys):
    frames = _all_frames(slaves=(1, 2))  # EM-3 (unit 3) silent
    frames += [(req, resp) for req, resp in sim.build_slave_frames(3, 1)][:1]
    proxies = {"EM-1": {"type": "PM5561", "modbus_slave_id": 1},
               "EM-2": {"type": "PM5111", "modbus_slave_id": 2},
               "EM-4": {"type": "PM8240", "modbus_slave_id": 4}}
    rc = frame_report.main(["-c", _write_config(tmp_path, proxies), _capture(tmp_path, frames)])
    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_PROBLEMS
    assert "EM-4 (unit 4, PM8240): no frames" in out
    assert "unit 3: 1 frames but not in site_details.proxy_ids" in out


def test_partial_polling_and_rejected_blocks_are_reported(tmp_path, capsys):
    frames = sim.build_slave_frames(1, 1, fail_registers={3028})  # the block with 3028 answers 0x02
    proxies = {"EM-1": {"type": "PM5561", "modbus_slave_id": 1}}
    rc = frame_report.main(["-c", _write_config(tmp_path, proxies), _capture(tmp_path, frames)])
    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_PROBLEMS
    assert "register-map points were not seen" in out
    assert "rejects these blocks" in out


def test_not_available_registers_are_reported(tmp_path, capsys):
    frames = sim.build_slave_frames(1, 1, na_registers={3110})
    proxies = {"EM-1": {"type": "PM5561", "modbus_slave_id": 1}}
    rc = frame_report.main(["-c", _write_config(tmp_path, proxies), _capture(tmp_path, frames)])
    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_PROBLEMS
    assert "registers 3110 report 'not available'" in out


def test_a_point_split_by_the_polled_blocks_is_not_polled(tmp_path, capsys):
    """A FLOAT32 point needs both registers: a block that reads only the first one does not count."""
    frames = [(req, resp) for req, resp in sim.build_slave_frames(1, 1) if not _reads(req, 3028)]
    request = append_modbus_crc16(struct.pack(">BBHH", 1, 3, 3027, 1))  # register 3028 only
    response = append_modbus_crc16(struct.pack(">BBB", 1, 3, 2) + b"\x43\x66")
    frames.append((request, response))
    proxies = {"EM-1": {"type": "PM5561", "modbus_slave_id": 1}}
    rc = frame_report.main(["-c", _write_config(tmp_path, proxies), _capture(tmp_path, frames)])
    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_PROBLEMS
    not_polled = next(line for line in out.splitlines() if line.strip().startswith("not polled:"))
    assert "line1_neutral_voltage_sensor" in not_polled


def test_empty_capture_and_bad_usage(tmp_path, capsys):
    empty = tmp_path / "empty.txt"
    empty.write_text("not a frame\n", encoding="utf-8")
    assert frame_report.main(["-c", _write_config(tmp_path), str(empty)]) == frame_report.EXIT_PROBLEMS
    assert "No MXcloudgate frames" in capsys.readouterr().out
    assert frame_report.main(["-c", str(tmp_path / "missing.json"), str(empty)]) == frame_report.EXIT_USAGE
    with pytest.raises(SystemExit) as exc:
        frame_report.main(["-c", _write_config(tmp_path)])  # neither a capture nor --live
    assert exc.value.code == 2
