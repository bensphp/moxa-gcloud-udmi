# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Modbus RTU decoder tests (independent reference vectors, not self-generated CRCs)."""

import json
import struct

import pytest

from google_iot_core_gateway.modbus_gw.modbus_to_json import (
    append_modbus_crc16,
    compute_modbus_crc16,
    modbus_to_json,
    verify_modbus_crc16,
)
import mxcloudgate_simulator as sim

SLAVES = {1: "PM5561", 2: "PM5111", 3: "PM8240"}


def _frames(start_register, qty, data: bytes, slave=1):
    req = append_modbus_crc16(struct.pack(">BBHH", slave, 3, start_register - 1, qty))
    resp = append_modbus_crc16(struct.pack(">BBB", slave, 3, len(data)) + data)
    return req, resp


def _decode(req, resp, **kwargs):
    return json.loads(modbus_to_json(req, resp, slave_to_type=SLAVES, **kwargs))


class TestCrc:
    @pytest.mark.parametrize(
        "frame_hex",
        [
            "01030000000ac5cd",  # Read 10 holding registers from unit 1 (common reference frame)
            "1103006b00037687",  # Modbus serial line spec / Simply Modbus example frame
        ],
    )
    def test_known_reference_frames(self, frame_hex):
        frame = bytes.fromhex(frame_hex)
        assert verify_modbus_crc16(frame)
        assert compute_modbus_crc16(frame[:-2]) == struct.unpack("<H", frame[-2:])[0]

    def test_bit_flip_is_detected(self):
        frame = bytearray.fromhex("1103006b00037687")
        frame[3] ^= 0x01
        assert not verify_modbus_crc16(bytes(frame))


class TestDecoder:
    def test_float32_decoding_and_request_metadata(self):
        req, resp = _frames(3028, 2, struct.pack(">f", 230.1))
        decoded = _decode(req, resp)
        assert decoded["error"] is None
        assert decoded["data"]["3028"] == 230.1  # 7 significant digits, no float32 noise
        assert decoded["start_register"] == 3028
        assert decoded["quantity"] == 2

    def test_small_float32_values_keep_their_precision(self):
        for value in (4e-07, 0.00098765):
            req, resp = _frames(3028, 2, struct.pack(">f", value))
            assert _decode(req, resp)["data"]["3028"] == pytest.approx(value, rel=1e-6)

    def test_request_length_is_checked(self):
        _, resp = _frames(3028, 2, struct.pack(">f", 230.5))
        seven_byte_request = struct.pack(">BBHH", 1, 3, 3027, 2) + b"\x00"
        assert _decode(seven_byte_request, resp)["error_kind"] == "framing"
        six_byte_request = struct.pack(">BBHH", 1, 3, 3027, 2)  # no CRC forwarded
        assert _decode(six_byte_request, resp)["data"]["3028"] == 230.5

    def test_nan_is_reported_as_unavailable_not_dropped(self):
        req, resp = _frames(3028, 2, struct.pack(">f", float("nan")))
        decoded = _decode(req, resp)
        assert "3028" not in decoded["data"]
        assert decoded["unavailable"]["3028"].startswith("N/A(")

    def test_integer_not_available_sentinel(self):
        # PM5561 3216 is an INT64 energy register; 0x8000000000000000 means "not available".
        req, resp = _frames(3216, 4, struct.pack(">q", -0x8000000000000000))
        decoded = _decode(req, resp)
        assert "3216" not in decoded["data"]
        assert "3216" in decoded["unavailable"]

    def test_zero_crc_is_not_a_bypass(self):
        req, _ = _frames(3028, 2, struct.pack(">f", 230.5))
        resp = struct.pack(">BBB", 1, 3, 4) + struct.pack(">f", 0.0) + b"\x00\x00"
        decoded = _decode(req, resp)
        assert decoded["error_kind"] == "crc"
        assert decoded["data"] is None

    def test_crc_check_can_be_disabled_explicitly(self):
        req, _ = _frames(3028, 2, struct.pack(">f", 230.5))
        resp = struct.pack(">BBB", 1, 3, 4) + struct.pack(">f", 230.5) + b"\x00\x00"
        decoded = _decode(req, resp, strict_crc=False)
        assert decoded["data"]["3028"] == pytest.approx(230.5)

    def test_request_crc_mismatch(self):
        req, resp = _frames(3028, 2, struct.pack(">f", 230.5))
        bad_req = req[:-1] + bytes([req[-1] ^ 0xFF])
        assert _decode(bad_req, resp)["error_kind"] == "crc"

    def test_exception_response(self):
        req, _ = _frames(3000, 2, b"\x00" * 4)
        exc_resp = append_modbus_crc16(struct.pack(">BBB", 1, 0x83, 0x02))
        decoded = _decode(req, exc_resp)
        assert decoded["error_kind"] == "exception"
        assert decoded["exception_code"] == 2
        assert "illegal data address" in decoded["error"]

    def test_framing_errors(self):
        req, _ = _frames(3028, 2, struct.pack(">f", 1.0))
        wrong_count = append_modbus_crc16(struct.pack(">BBB", 1, 3, 2) + b"\x00\x01")
        assert _decode(req, wrong_count)["error_kind"] == "framing"
        other_slave = append_modbus_crc16(struct.pack(">BBB", 2, 3, 4) + struct.pack(">f", 1.0))
        assert _decode(req, other_slave)["error_kind"] == "framing"
        assert _decode(req, b"\x01\x03")["error_kind"] == "truncated"

    def test_string_and_int16u_registers(self):
        req, resp = _frames(1637, 1, struct.pack(">H", 104))
        assert _decode(req, resp)["data"]["1637"] == 104
        raw = b"SN-PM8240-7788".ljust(40, b"\x00")
        req, resp = _frames(117, 20, raw, slave=3)
        assert _decode(req, resp)["data"]["117"] == "SN-PM8240-7788"

    @pytest.mark.parametrize("slave_id", sorted(SLAVES))
    def test_simulator_frames_cover_every_map_register(self, slave_id):
        meter_map = sim.load_meter_map(SLAVES[slave_id])
        expected = {k for k in meter_map if k != "system"} | set(meter_map.get("system", {}))
        decoded_regs = set()
        for req, resp in sim.build_slave_frames(slave_id, 1):
            decoded = _decode(req, resp)
            assert decoded["error"] is None
            decoded_regs |= set(decoded["data"])
        assert expected <= decoded_regs
