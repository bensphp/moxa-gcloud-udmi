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


def test_generic_device_is_accepted_without_register_map(tmp_path, capsys):
    frames = sim.build_slave_frames(1, 1)
    proxies = {"GEN-1": {"type": "generic", "modbus_slave_id": 1}}
    rc = frame_report.main(["-c", _write_config(tmp_path, proxies), _capture(tmp_path, frames)])
    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_READY, out
    assert "generic Modbus device" in out


def test_empty_capture_and_bad_usage(tmp_path, capsys):
    empty = tmp_path / "empty.txt"
    empty.write_text("not a frame\n", encoding="utf-8")
    assert frame_report.main(["-c", _write_config(tmp_path), str(empty)]) == frame_report.EXIT_PROBLEMS
    assert "No MXcloudgate frames" in capsys.readouterr().out
    assert frame_report.main(["-c", str(tmp_path / "missing.json"), str(empty)]) == frame_report.EXIT_USAGE
    with pytest.raises(SystemExit) as exc:
        frame_report.main(["-c", _write_config(tmp_path)])  # neither a capture nor --live
    assert exc.value.code == 2


def _build_register_lookup(slave_id, extra_fc_regs=None):
    """Build {(fc, reg_1based): 2_byte_word} from simulator frames plus optional extras."""
    reg_words = {}
    for req, resp in sim.build_slave_frames(slave_id, 1):
        req_fc = req[1]
        start_reg = int.from_bytes(req[2:4], "big") + 1
        qty = int.from_bytes(req[4:6], "big")
        data_bytes = resp[3:-2]
        for idx in range(qty):
            reg_words[(req_fc, start_reg + idx)] = data_bytes[idx * 2 : idx * 2 + 2]
    if extra_fc_regs:
        for (req_fc, reg_addr), raw_bytes in extra_fc_regs.items():
            for idx in range(0, len(raw_bytes), 2):
                reg_words[(req_fc, reg_addr + (idx // 2))] = raw_bytes[idx : idx + 2]
    return reg_words


def _answer_modbus_pdu(reg_words, unit_id, pdu_bytes):
    req_fc = pdu_bytes[0]
    start_reg = int.from_bytes(pdu_bytes[1:3], "big") + 1
    qty = int.from_bytes(pdu_bytes[3:5], "big")
    if req_fc not in (3, 4):
        return bytes([unit_id, req_fc | 0x80, 0x01])
    payload = bytearray([unit_id, req_fc, qty * 2])
    for offset in range(qty):
        payload.extend(reg_words.get((req_fc, start_reg + offset), b"\x00\x00"))
    return bytes(payload)


class _ModbusTCPTestServer:
    """Minimal multi-FC Modbus TCP server for frame_report and E2E tests."""

    def __init__(self, registers_by_slave):
        import socket
        import threading

        self._registers_by_slave = registers_by_slave
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self._sock.settimeout(0.1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        import socket

        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(0.2)
            try:
                while not self._stop.is_set():
                    try:
                        mbap = conn.recv(7)
                    except socket.timeout:
                        continue
                    if not mbap or len(mbap) < 7:
                        break
                    tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", mbap)
                    pdu = conn.recv(length - 1)
                    if len(pdu) < 5:
                        break
                    reg_words = self._registers_by_slave.get(unit_id, {})
                    body = _answer_modbus_pdu(reg_words, unit_id, pdu)
                    resp_mbap = struct.pack(">HHH", tx_id, proto_id, len(body))
                    conn.sendall(resp_mbap + body)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


class _PtyRtuResponder:
    """Modbus RTU slave responder attached to the master side of a pty pair."""

    def __init__(self, master_fd, registers_by_slave):
        import os
        import select
        import threading

        self._master_fd = master_fd
        self._registers_by_slave = registers_by_slave
        self._os = os
        self._select = select
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        from google_iot_core_gateway.modbus_gw.modbus_to_json import verify_modbus_crc16

        buf = bytearray()
        while not self._stop.is_set():
            try:
                readable, _wr, _ex = self._select.select([self._master_fd], [], [], 0.05)
            except (OSError, ValueError):
                break
            if not readable:
                continue
            try:
                chunk = self._os.read(self._master_fd, 256)
            except OSError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            while len(buf) >= 8:
                frame = bytes(buf[:8])
                del buf[:8]
                if not verify_modbus_crc16(frame):
                    continue
                unit_id = frame[0]
                reg_words = self._registers_by_slave.get(unit_id, {})
                body = _answer_modbus_pdu(reg_words, unit_id, frame[1:6])
                self._os.write(self._master_fd, append_modbus_crc16(body))

    def close(self):
        self._stop.set()
        self._thread.join(timeout=5)


def test_mutually_exclusive_and_save_usage_errors(tmp_path):
    cfg = _write_config(tmp_path)
    for bad_argv in (
        ["-c", cfg, "--live", "1", "--poll-tcp", "1"],
        ["-c", cfg, "--save", str(tmp_path / "out.jsonl"), str(tmp_path / "in.jsonl")],
        ["-c", cfg, "--poll-tcp", "0"],
        ["-c", cfg, "--poll-serial", "-1"],
    ):
        with pytest.raises(SystemExit) as exc:
            frame_report.main(bad_argv)
        assert exc.value.code == 2


def test_poll_tcp_handles_fc03_and_fc04_and_saves_capture(tmp_path, capsys):
    from conftest import write_site_model

    site_dir = write_site_model(
        tmp_path,
        meter_points={
            "line1_neutral_voltage_sensor": {"units": "Volts", "ref": "3/3028/2?type=FLOAT32"},
            "frequency_sensor": {"units": "Hertz", "ref": "3/3110/2?type=FLOAT32"},
            "input_register_voltage": {"units": "Volts", "ref": "4/4000/2?type=FLOAT32"},
        },
    )
    reg_words = _build_register_lookup(1, extra_fc_regs={(4, 4000): struct.pack(">f", 234.5)})
    server = _ModbusTCPTestServer({1: reg_words})
    cfg_path = tmp_path / "tcp-cfg.json"
    cfg_path.write_text(
        json.dumps(
            {
                "internal_broker": {"enabled": False},
                "modbus": {
                    "transport": "tcp",
                    "poll_host": "127.0.0.1",
                    "poll_port": server.port,
                    "poll_interval_sec": 0.2,
                    "poll_timeout_sec": 1.0,
                },
                "site_details": {
                    "gateway_id": "CGW-1",
                    "proxy_ids": {"EM-1": {"type": "PM5561", "modbus_slave_id": 1}},
                },
                "environment_setup": {
                    "resources_path": RESOURCES_DIR,
                    "udmi_site_model_path": str(site_dir),
                },
            }
        ),
        encoding="utf-8",
    )
    saved_path = tmp_path / "tcp-capture.jsonl"
    try:
        rc = frame_report.main(["-c", str(cfg_path), "--poll-tcp", "0.35", "--save", str(saved_path)])
    finally:
        server.close()

    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_READY, out
    assert "READY" in out
    assert "52110001" in out
    saved_lines = [json.loads(line) for line in saved_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert saved_lines
    fcs_seen = {bytes.fromhex(item["rtu_request"])[1] for item in saved_lines}
    assert fcs_seen == {3, 4}
    assert frame_report.main(["-c", str(cfg_path), str(saved_path)]) == frame_report.EXIT_READY


def test_poll_serial_over_pty_saves_capture(tmp_path, capsys):
    import os
    import pty

    from conftest import write_site_model

    site_dir = write_site_model(
        tmp_path,
        meter_points={
            "line1_neutral_voltage_sensor": {"units": "Volts", "ref": "3/3028/2?type=FLOAT32"},
            "input_register_current": {"units": "Amperes", "ref": "4/4010/2?type=FLOAT32"},
        },
    )
    master_fd, slave_fd = pty.openpty()
    slave_path = os.ttyname(slave_fd)
    reg_words = _build_register_lookup(1, extra_fc_regs={(4, 4010): struct.pack(">f", 12.25)})
    responder = _PtyRtuResponder(master_fd, {1: reg_words})
    cfg_path = tmp_path / "rtu-cfg.json"
    cfg_path.write_text(
        json.dumps(
            {
                "internal_broker": {"enabled": False},
                "modbus": {
                    "transport": "rtu",
                    "serial_ports": {"ttyM0": slave_path},
                    "baudrate": 19200,
                    "parity": "E",
                    "stopbits": 1,
                    "poll_interval_sec": 0.2,
                    "poll_timeout_sec": 1.0,
                },
                "site_details": {
                    "gateway_id": "CGW-1",
                    "proxy_ids": {"EM-1": {"type": "PM5561", "modbus_slave_id": 1, "port": "ttyM0"}},
                },
                "environment_setup": {
                    "resources_path": RESOURCES_DIR,
                    "udmi_site_model_path": str(site_dir),
                },
            }
        ),
        encoding="utf-8",
    )
    saved_path = tmp_path / "rtu-capture.jsonl"
    try:
        rc = frame_report.main(["-c", str(cfg_path), "--poll-serial", "0.35", "--save", str(saved_path)])
    finally:
        responder.close()
        os.close(slave_fd)
        os.close(master_fd)

    out = capsys.readouterr().out
    assert rc == frame_report.EXIT_READY, out
    assert "READY" in out
    assert "52110001" in out
    saved_lines = [json.loads(line) for line in saved_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert saved_lines
    fcs_seen = {bytes.fromhex(item["rtu_request"])[1] for item in saved_lines}
    assert fcs_seen == {3, 4}
    assert frame_report.main(["-c", str(cfg_path), str(saved_path)]) == frame_report.EXIT_READY

