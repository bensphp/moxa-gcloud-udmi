# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Tests for the optional built-in Modbus TCP poller."""

import json
import queue
import socketserver
import struct
import threading
import time

from conftest import RESOURCES_DIR, write_site_model
from google_iot_core_gateway.gcp_handler import process_payloads
from google_iot_core_gateway.modbus_gw.modbus_tcp_poller import ModbusTCPPoller
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
