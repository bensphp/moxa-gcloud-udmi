# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Tests for the optional built-in Modbus TCP poller."""

import errno
import json
import os
import pty
import queue
import select
import socketserver
import struct
import threading
import time

import pytest

from conftest import RESOURCES_DIR, write_site_model
from google_iot_core_gateway.gcp_handler import process_payloads
from google_iot_core_gateway.modbus_gw.modbus_rtu_poller import (
    ModbusRTUPoller,
    build_modbus_rtu_read_request,
    resolve_serial_device,
)
from google_iot_core_gateway.modbus_gw.modbus_tcp_poller import (
    ModbusTCPPoller,
    build_modbus_tcp_fc3_request,
    build_modbus_tcp_read_request,
)
from google_iot_core_gateway.modbus_gw.modbus_to_json import (
    append_modbus_crc16,
    decode_modbus_frame,
    verify_modbus_crc16,
)
from google_iot_core_gateway.udmi_handler import udmi_handler as module
from helpers import config as _config, frame as _frame, meter_config as _meter_config, state_of as _state


class _ModbusTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, registers=None):
        self.registers = registers or {}
        self.exceptions = {}
        self.requests = []
        super().__init__(server_address, handler_class)


class _ModbusHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            header = self._recv_exact(7)
            if not header:
                return
            tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", header)
            pdu = self._recv_exact(length - 1)
            if not pdu or proto_id != 0:
                return
            fc = pdu[0]
            start_pdu, qty = struct.unpack(">HH", pdu[1:5])
            start_reg = start_pdu + 1
            self.server.requests.append((unit_id, fc, start_reg, qty))

            fail_regs = self.server.exceptions.get(unit_id, set())
            if any(start_reg <= r < start_reg + qty for r in fail_regs):
                resp_pdu = struct.pack(">BB", fc | 0x80, 0x02)
            else:
                regs = self.server.registers.get(unit_id, {})
                words = [regs.get(start_reg + i, 0) for i in range(qty)]
                resp_pdu = struct.pack(">BB", fc, qty * 2) + b"".join(struct.pack(">H", w) for w in words)

            mbap = struct.pack(">HHHB", tx_id, 0, len(resp_pdu) + 1, unit_id)
            self.request.sendall(mbap + resp_pdu)

    def _recv_exact(self, nbytes):
        buf = bytearray()
        while len(buf) < nbytes:
            chunk = self.request.recv(nbytes - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)


def _encode_float32_words(val: float) -> list:
    raw = struct.pack(">f", val)
    return list(struct.unpack(">HH", raw))


def _encode_uint32_words(val: int) -> list:
    raw = struct.pack(">I", val)
    return list(struct.unpack(">HH", raw))


def _start_modbus_server():
    registers = {
        1: {
            130: _encode_uint32_words(52110001)[0],
            131: _encode_uint32_words(52110001)[1],
            1637: 1103,
            3028: _encode_float32_words(231.5)[0],
            3029: _encode_float32_words(231.5)[1],
            3110: _encode_float32_words(50.0)[0],
            3111: _encode_float32_words(50.0)[1],
        },
        4: {
            100: 245,
        },
    }
    server = _ModbusTCPServer(("127.0.0.1", 0), _ModbusHandler, registers=registers)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_active_mode_polls_pm5561_and_generic_without_external_poller(tmp_path, logger, monkeypatch):
    monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
    site = write_site_model(tmp_path)
    h = module.UDMIHandler(logger, RESOURCES_DIR, str(site), config_wait_timeout_sec=0)
    h.add_device_to_dict(1, "EM-1", "PM5561", port="ttyM0")
    h.add_device_to_dict(4, "GEN-1", "generic", port="ttyM1")
    h.register_gateway("CGW-1", proxy_ids=["EM-1", "GEN-1"], serial_no="GW-POLL")
    h.handle_config("EM-1", _meter_config())
    h.handle_config(
        "GEN-1",
        _config(
            "2026-11-16T12:00:00Z",
            gateway={"target": {"family": "modbus", "addr": "ttyM1", "unitid": "4"}},
            pointset={"points": {"temp_sensor": {"ref": "3/100/1?type=INT16", "units": "Celsius"}}},
        ),
    )

    server = _start_modbus_server()
    try:
        q = queue.Queue()
        poller = ModbusTCPPoller(
            logger, q, h, host="127.0.0.1", port=server.server_address[1], mode="active", interval_sec=10.0
        )
        assert poller.poll_once() >= 2
        assert process_payloads(logger, q, h) >= 2
        assert _state(h, "EM-1")["system"]["serial_no"] == "52110001"
        assert _state(h, "EM-1")["system"]["software"]["firmware"] == "1103"
        assert json.loads(h.get_event_point_payload("EM-1"))["points"] == {
            "line1_neutral_voltage_sensor": {"present_value": 231.5},
            "frequency_sensor": {"present_value": 50.0},
        }
        assert json.loads(h.get_event_point_payload("GEN-1"))["points"] == {
            "temp_sensor": {"present_value": 245}
        }
        poller.stop()
    finally:
        server.shutdown()
        server.server_close()


def test_fallback_mode_polls_only_missing_identity_and_unpolled_points(handler_factory, logger):
    h = handler_factory(stale_timeout_sec=300.0)
    h.handle_config("EM-1", _meter_config())
    # External poller already supplied 3028 recently, while 3110 and identity are missing.
    h.record_modbus_payload(_frame({3028: 230.0}, start=3028, qty=2))

    server = _start_modbus_server()
    try:
        q = queue.Queue()
        poller = ModbusTCPPoller(
            logger, q, h, host="127.0.0.1", port=server.server_address[1], mode="fallback", interval_sec=5.0
        )
        assert poller.poll_once() >= 1
        req_spans = [(u, start, start + qty - 1) for (u, _fc, start, qty) in server.requests]
        assert any(u == 1 and s <= 3110 <= e for u, s, e in req_spans)
        assert any(u == 1 and s <= 130 <= e for u, s, e in req_spans)
        assert not any(u == 1 and s <= 3028 <= e for u, s, e in req_spans)

        process_payloads(logger, q, h)
        assert _state(h, "EM-1")["system"]["serial_no"] == "52110001"
        # Once identity + both points are fresh, fallback does no redundant polling.
        assert poller.poll_once() == 0
        poller.stop()
    finally:
        server.shutdown()
        server.server_close()


def test_poller_surfaces_modbus_exceptions_and_stops_promptly(handler_factory, logger):
    h = handler_factory()
    h.handle_config("EM-1", _meter_config())
    server = _start_modbus_server()
    server.exceptions[1] = {3028}
    try:
        q = queue.Queue()
        poller = ModbusTCPPoller(
            logger, q, h, host="127.0.0.1", port=server.server_address[1], mode="active", interval_sec=10.0
        )
        poller.poll_once()
        process_payloads(logger, q, h)
        points = _state(h, "EM-1")["pointset"]["points"]
        assert points["line1_neutral_voltage_sensor"]["value_state"] == "failure"
        assert "0x02" in points["line1_neutral_voltage_sensor"]["status"]["message"]
        assert points["frequency_sensor"] == {}

        poller.start()
        t0 = time.monotonic()
        poller.stop(timeout=2.0)
        assert time.monotonic() - t0 < 0.5
    finally:
        server.shutdown()
        server.server_close()


class _FCModbusTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, registers_by_fc=None):
        self.registers_by_fc = registers_by_fc or {}
        self.exceptions_by_fc = {}
        self.requests = []
        super().__init__(server_address, handler_class)


class _FCModbusHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            header = self._recv_exact(7)
            if not header:
                return
            tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", header)
            pdu = self._recv_exact(length - 1)
            if not pdu or proto_id != 0:
                return
            fc = pdu[0]
            start_pdu, qty = struct.unpack(">HH", pdu[1:5])
            start_reg = start_pdu + 1
            self.server.requests.append((unit_id, fc, start_reg, qty))

            fail_regs = self.server.exceptions_by_fc.get((unit_id, fc), set())
            if any(start_reg <= reg < start_reg + qty for reg in fail_regs):
                resp_pdu = struct.pack(">BB", fc | 0x80, 0x02)
            else:
                regs = self.server.registers_by_fc.get((unit_id, fc), {})
                words = [regs.get(start_reg + i, 0) for i in range(qty)]
                resp_pdu = struct.pack(">BB", fc, qty * 2) + b"".join(
                    struct.pack(">H", word) for word in words
                )

            mbap = struct.pack(">HHHB", tx_id, 0, len(resp_pdu) + 1, unit_id)
            self.request.sendall(mbap + resp_pdu)

    def _recv_exact(self, nbytes):
        buf = bytearray()
        while len(buf) < nbytes:
            chunk = self.request.recv(nbytes - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)


class _RTUSlaveEmulator:
    """Simulated Modbus RTU slave responder attached to a POSIX pty.openpty() pair."""

    def __init__(self, registers_by_fc=None):
        self.master_fd, self.slave_fd = pty.openpty()
        self.slave_path = os.ttyname(self.slave_fd)
        self.registers_by_fc = registers_by_fc or {}
        self.exceptions_by_fc = {}
        self.requests = []
        self.silent = False
        self.corrupt_crc_once = False
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()
        return self

    def _serve_loop(self):
        buf = bytearray()
        while not self._stop_event.is_set():
            readable, _writable, _exceptional = select.select([self.master_fd], [], [], 0.05)
            if not readable:
                continue
            try:
                chunk = os.read(self.master_fd, 256)
            except OSError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            while len(buf) >= 8:
                req = bytes(buf[:8])
                del buf[:8]
                if not verify_modbus_crc16(req):
                    continue
                unit_id, fc, start_pdu, qty = struct.unpack(">BBHH", req[:6])
                start_reg = start_pdu + 1
                self.requests.append((unit_id, fc, start_reg, qty))
                if self.silent:
                    continue
                fail_regs = self.exceptions_by_fc.get((unit_id, fc), set())
                if any(start_reg <= reg < start_reg + qty for reg in fail_regs):
                    resp = append_modbus_crc16(struct.pack(">BBB", unit_id, fc | 0x80, 0x02))
                else:
                    regs = self.registers_by_fc.get((unit_id, fc), {})
                    words = [regs.get(start_reg + i, 0) for i in range(qty)]
                    body = struct.pack(">BBB", unit_id, fc, qty * 2) + b"".join(
                        struct.pack(">H", word) for word in words
                    )
                    resp = append_modbus_crc16(body)
                if self.corrupt_crc_once:
                    self.corrupt_crc_once = False
                    resp = resp[:-1] + bytes([resp[-1] ^ 0xFF])
                os.write(self.master_fd, resp)

    def stop(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        for fd_val in (self.master_fd, self.slave_fd):
            if fd_val is not None:
                try:
                    os.close(fd_val)
                except OSError:
                    pass
        self.master_fd = None
        self.slave_fd = None


def test_build_modbus_tcp_read_request_supports_fc3_and_fc4():
    fc3 = build_modbus_tcp_read_request(7, 1, 3, 3028, 2)
    assert fc3 == build_modbus_tcp_fc3_request(7, 1, 3028, 2)
    fc4 = build_modbus_tcp_read_request(8, 2, 4, 100, 1)
    assert fc4[6:] == bytes([2, 4, 0, 99, 0, 1])
    with pytest.raises(ValueError):
        build_modbus_tcp_read_request(1, 1, 5, 100, 1)


def test_tcp_poller_fc03_and_fc04_isolation_end_to_end(tmp_path, logger, monkeypatch):
    monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
    site = write_site_model(tmp_path)
    handler = module.UDMIHandler(logger, RESOURCES_DIR, str(site), config_wait_timeout_sec=0)
    assert handler.add_device_to_dict(1, "EM-1", "PM5561", port="ttyM0")
    assert handler.add_device_to_dict(4, "GEN-1", "generic", port="ttyM1")
    assert handler.register_gateway("CGW-1", proxy_ids=["EM-1", "GEN-1"], serial_no="GW-FC")

    handler.handle_config(
        "EM-1",
        _meter_config(
            points={
                "line1_neutral_voltage_sensor": {"ref": "3/3028/2?type=FLOAT32"},
                "input_voltage_sensor": {"ref": "4/3028/2?type=FLOAT32"},
            }
        ),
    )
    handler.handle_config(
        "GEN-1",
        _config(
            "2026-11-16T12:00:00Z",
            gateway={"target": {"family": "modbus", "addr": "ttyM1", "unitid": "4"}},
            pointset={
                "points": {
                    "holding_word": {"ref": "3/100/1?type=INT16"},
                    "input_word": {"ref": "4/100/1?type=INT16"},
                }
            },
        ),
    )

    registers_by_fc = {
        (1, 3): {
            130: _encode_uint32_words(52110001)[0],
            131: _encode_uint32_words(52110001)[1],
            1637: 1103,
            3028: _encode_float32_words(231.5)[0],
            3029: _encode_float32_words(231.5)[1],
        },
        (1, 4): {
            3028: _encode_float32_words(244.25)[0],
            3029: _encode_float32_words(244.25)[1],
        },
        (4, 3): {100: 111},
        (4, 4): {100: 222},
    }
    server = _FCModbusTCPServer(("127.0.0.1", 0), _FCModbusHandler, registers_by_fc=registers_by_fc)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        frame_queue = queue.Queue()
        poller = ModbusTCPPoller(
            logger,
            frame_queue,
            handler,
            host="127.0.0.1",
            port=server.server_address[1],
            mode="active",
            interval_sec=10.0,
        )
        assert poller.poll_once() >= 4
        assert process_payloads(logger, frame_queue, handler) >= 4

        em_points = json.loads(handler.get_event_point_payload("EM-1"))["points"]
        assert em_points == {
            "line1_neutral_voltage_sensor": {"present_value": 231.5},
            "input_voltage_sensor": {"present_value": 244.25},
        }
        gen_points = json.loads(handler.get_event_point_payload("GEN-1"))["points"]
        assert gen_points == {
            "holding_word": {"present_value": 111},
            "input_word": {"present_value": 222},
        }

        # FC03 exception at 3028 must not clobber FC04 read at 3028 (wait past error grace).
        server.exceptions_by_fc[(1, 3)] = {3028}
        assert poller.poll_once() >= 4
        assert process_payloads(logger, frame_queue, handler) >= 4
        # Force an FC03 exception with updated_mono outside grace window via direct record check
        handler.record_modbus_payload(
            {
                "slave_id": 1,
                "fc": 3,
                "start_register": 3028,
                "quantity": 2,
                "data": None,
                "unavailable": {},
                "error": "Modbus exception code 0x02 (illegal data address)",
                "error_kind": "exception",
                "exception_code": 2,
            },
            now_mono=time.monotonic() + handler.error_grace_sec + 5.0,
        )
        em_state = _state(handler, "EM-1")["pointset"]["points"]
        assert em_state["line1_neutral_voltage_sensor"]["value_state"] == "failure"
        assert em_state["input_voltage_sensor"] == {}
        poller.stop()
    finally:
        server.shutdown()
        server.server_close()


class _LegacyMockHandler:
    def get_poll_targets(self, _mode, poll_interval_sec=10.0):
        return [(4, [(100, 1)])]


def test_tcp_poller_falls_back_to_get_poll_targets_when_mocked(logger):
    server = _FCModbusTCPServer(
        ("127.0.0.1", 0), _FCModbusHandler, registers_by_fc={(4, 3): {100: 321}}
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        frame_queue = queue.Queue()
        poller = ModbusTCPPoller(
            logger,
            frame_queue,
            _LegacyMockHandler(),
            host="127.0.0.1",
            port=server.server_address[1],
            mode="active",
        )
        assert poller.poll_once() == 1
        assert server.requests == [(4, 3, 100, 1)]
        msg = json.loads(frame_queue.get_nowait())
        decoded = decode_modbus_frame(
            bytes.fromhex(msg["rtu_request"]),
            bytes.fromhex(msg["rtu_response"]),
            slave_to_type={4: "__m"},
            dbo_maps={"__m": {"100": {"dbo_name": "p", "number_of_registers": 1, "format": "int16"}}},
        )
        assert decoded["fc"] == 3
        assert decoded["data"]["100"] == 321
        poller.stop()
    finally:
        server.shutdown()
        server.server_close()


def test_rtu_helpers_resolve_and_request_validation():
    assert (
        resolve_serial_device("ttyM0", serial_ports_map={"ttyM0": "/dev/pts/9"}, default_port="ttyM1")
        == "/dev/pts/9"
    )
    assert resolve_serial_device("ttyM0", device_prefix="/dev") == "/dev/ttyM0"
    assert resolve_serial_device(None, default_port="/dev/ttyS1") == "/dev/ttyS1"
    with pytest.raises(ValueError):
        resolve_serial_device(None)

    req_fc3 = build_modbus_rtu_read_request(1, 3, 3028, 2)
    req_fc4 = build_modbus_rtu_read_request(1, 4, 3028, 2)
    assert len(req_fc3) == 8 and verify_modbus_crc16(req_fc3)
    assert len(req_fc4) == 8 and verify_modbus_crc16(req_fc4)
    assert req_fc4[1] == 4
    with pytest.raises(ValueError):
        build_modbus_rtu_read_request(1, 6, 100, 1)
    with pytest.raises(ValueError):
        build_modbus_rtu_read_request(256, 3, 100, 1)
    with pytest.raises(ValueError):
        build_modbus_rtu_read_request(1, 3, 0, 1)
    with pytest.raises(ValueError):
        build_modbus_rtu_read_request(1, 3, 1, 126)


def test_rtu_poller_multi_port_pty_fc03_and_fc04_and_fd_cleanup(tmp_path, logger, monkeypatch):
    monkeypatch.setattr(module, "detect_hardware_serial", lambda: None)
    site = write_site_model(tmp_path)
    handler = module.UDMIHandler(logger, RESOURCES_DIR, str(site), config_wait_timeout_sec=0)
    assert handler.add_device_to_dict(1, "EM-1", "PM5561", port="ttyM0")
    assert handler.add_device_to_dict(4, "GEN-1", "generic", port="ttyM1")
    assert handler.register_gateway("CGW-1", proxy_ids=["EM-1", "GEN-1"], serial_no="GW-RTU")
    handler.handle_config(
        "EM-1",
        _meter_config(
            points={
                "line1_neutral_voltage_sensor": {"ref": "3/3028/2?type=FLOAT32"},
                "frequency_sensor": {"ref": "4/3110/2?type=FLOAT32"},
            }
        ),
    )
    handler.handle_config(
        "GEN-1",
        _config(
            "2026-11-16T12:00:00Z",
            gateway={"target": {"family": "modbus", "addr": "ttyM1", "unitid": "4"}},
            pointset={
                "points": {
                    "holding_temp": {"ref": "3/100/1?type=INT16"},
                    "input_temp": {"ref": "4/100/1?type=INT16"},
                }
            },
        ),
    )

    emu0 = _RTUSlaveEmulator(
        registers_by_fc={
            (1, 3): {
                130: _encode_uint32_words(52110002)[0],
                131: _encode_uint32_words(52110002)[1],
                1637: 1104,
                3028: _encode_float32_words(230.25)[0],
                3029: _encode_float32_words(230.25)[1],
            },
            (1, 4): {
                3110: _encode_float32_words(50.0)[0],
                3111: _encode_float32_words(50.0)[1],
            },
        }
    ).start()
    emu1 = _RTUSlaveEmulator(
        registers_by_fc={
            (4, 3): {100: 150},
            (4, 4): {100: 275},
        }
    ).start()
    poller = None
    try:
        frame_queue = queue.Queue()
        poller = ModbusRTUPoller(
            logger,
            frame_queue,
            handler,
            mode="active",
            interval_sec=10.0,
            timeout_sec=1.0,
            serial_ports={"ttyM0": emu0.slave_path, "ttyM1": emu1.slave_path},
            baudrate=19200,
            rs485_mode=True,
        )
        assert poller.poll_once() >= 4
        assert process_payloads(logger, frame_queue, handler) >= 4
        assert _state(handler, "EM-1")["system"]["serial_no"] == "52110002"
        assert json.loads(handler.get_event_point_payload("EM-1"))["points"] == {
            "line1_neutral_voltage_sensor": {"present_value": 230.25},
            "frequency_sensor": {"present_value": 50.0},
        }
        assert json.loads(handler.get_event_point_payload("GEN-1"))["points"] == {
            "holding_temp": {"present_value": 150},
            "input_temp": {"present_value": 275},
        }

        open_fds = list(poller._fds.values())
        assert len(open_fds) == 2
        poller.start()
        t_start = time.monotonic()
        poller.stop(timeout=2.0)
        assert time.monotonic() - t_start < 0.5
        assert poller._fds == {}
        for closed_fd in open_fds:
            with pytest.raises(OSError) as err_info:
                os.fstat(closed_fd)
            assert err_info.value.errno == errno.EBADF
    finally:
        if poller is not None:
            poller.stop(timeout=1.0)
        emu0.stop()
        emu1.stop()


def test_rtu_poller_handles_exceptions_bad_crc_and_timeout_recovery(handler_factory, logger):
    handler = handler_factory()
    handler.handle_config(
        "EM-1",
        _meter_config(
            points={
                "line1_neutral_voltage_sensor": {"ref": "3/3028/2?type=FLOAT32"},
                "frequency_sensor": {"ref": "4/3110/2?type=FLOAT32"},
            }
        ),
    )
    emu = _RTUSlaveEmulator(
        registers_by_fc={
            (1, 3): {
                130: _encode_uint32_words(52110003)[0],
                131: _encode_uint32_words(52110003)[1],
                1637: 1105,
                3028: _encode_float32_words(232.0)[0],
                3029: _encode_float32_words(232.0)[1],
            },
            (1, 4): {
                3110: _encode_float32_words(50.0)[0],
                3111: _encode_float32_words(50.0)[1],
            },
        }
    ).start()
    poller = None
    try:
        frame_queue = queue.Queue()
        poller = ModbusRTUPoller(
            logger,
            frame_queue,
            handler,
            mode="active",
            interval_sec=10.0,
            timeout_sec=0.15,
            serial_ports={"ttyM0": emu.slave_path},
            baudrate=115200,
        )

        # 1. Timeout drops FD without hanging, then recovers cleanly once slave responds.
        emu.silent = True
        assert poller.poll_once() == 0
        assert poller._fds == {}

        emu.silent = False
        assert poller.poll_once() >= 2
        assert process_payloads(logger, frame_queue, handler) >= 2
        assert json.loads(handler.get_event_point_payload("EM-1"))["points"] == {
            "line1_neutral_voltage_sensor": {"present_value": 232.0},
            "frequency_sensor": {"present_value": 50.0},
        }

        # 2. Bad CRC frame is rejected and FD dropped; subsequent pass recovers.
        emu.corrupt_crc_once = True
        polled_bad = poller.poll_once()
        assert polled_bad == 1
        assert frame_queue.qsize() == 1
        queued_good = json.loads(frame_queue.get_nowait())
        assert verify_modbus_crc16(bytes.fromhex(queued_good["rtu_response"]))
        assert poller.poll_once() >= 2
        while not frame_queue.empty():
            frame_queue.get_nowait()

        # 3. Modbus exception on FC04 surfaces in state without clobbering FC03 point.
        handler.error_grace_sec = 0.0
        emu.exceptions_by_fc[(1, 4)] = {3110}
        assert poller.poll_once() >= 2
        assert process_payloads(logger, frame_queue, handler) >= 2
        points = _state(handler, "EM-1")["pointset"]["points"]
        assert points["frequency_sensor"]["value_state"] == "failure"
        assert "0x02" in points["frequency_sensor"]["status"]["message"]
        assert points["line1_neutral_voltage_sensor"] == {}
    finally:
        if poller is not None:
            poller.stop(timeout=1.0)
        emu.stop()
