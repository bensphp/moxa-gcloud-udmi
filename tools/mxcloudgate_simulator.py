#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""
Synthetic Moxa MXcloudgate Modbus RTU publisher for local testing and UDMI Sequencer validation.

Publishes CRC-16 valid Modbus FC03 request/response pairs onto the `MXcloudgate` MQTT topic in
the MXcloudgate JSON format ({"rtu_request": "<hex>", "rtu_response": "<hex>"}). Frames are built
from the meter register maps in resources/modbus_dbo_maps, including the identity registers
(serial number, firmware, manufacturer, model), so every point the gateway knows gets a value.

Fault injection for testing:
  --na 1:3028          meter 1 reports register 3028 as "not available" (NaN / sentinel)
  --fail-block 2:3000  meter 2 answers the request block containing register 3000 with
                       Modbus exception 0x02 (illegal data address)
"""

import argparse
import json
import random
import signal
import struct
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from google_iot_core_gateway.modbus_gw.modbus_to_json import append_modbus_crc16  # noqa: E402

MAPS_DIR = REPO_ROOT / "resources" / "modbus_dbo_maps"
MAX_BLOCK_REGISTERS = 120
MAX_BLOCK_GAP = 16

# Identity reported by each simulated meter (the site model must match what the meter reports).
DEFAULT_IDENTITIES = {
    1: {
        "type": "PM5561",
        "serial_no": 52110011,
        "firmware_version": 1103,
        "manufacturer_name": "Schneider Electric",
        "model_name": "PM5561",
        "product_name": "PowerLogic PM5561",
    },
    2: {
        "type": "PM5111",
        "serial_no": 51110012,
        "firmware_version": 1203,
        "manufacturer_name": "Schneider Electric",
        "model_name": "PM5111",
        "product_name": "PowerLogic PM5111",
    },
    3: {
        "type": "PM8240",
        "serial_no": "PM8240-0013",
        "firmware_version": "2.1.0",
        "manufacturer_name": "Schneider Electric",
        "model_name": "PM8240",
        "product_name": "PowerLogic PM8240",
    },
}

_INT_NA = {
    "int16u": 0xFFFF,
    "int16": -0x8000,
    "int32u": 0xFFFFFFFF,
    "int32": -0x80000000,
    "int64": -0x8000000000000000,
    "int64u": 0xFFFFFFFFFFFFFFFF,
}
_STRUCT = {
    "float32": ">f",
    "float64": ">d",
    "int16u": ">H",
    "int16": ">h",
    "int32u": ">I",
    "int32": ">i",
    "int64": ">q",
    "int64u": ">Q",
}


def load_meter_map(meter_type: str) -> dict:
    with open(MAPS_DIR / f"{meter_type}.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


def plausible_value(name: str, fmt: str, slave_id: int, tick: int):
    """Plausible 3-phase 230/400 V 50 Hz value for a DBO point name."""
    jitter = (slave_id * 0.1) + random.uniform(-0.05, 0.05)
    lname = name.lower()
    if "energy" in lname:
        wh = 125000 + slave_id * 1000 + tick * 5
        return wh if fmt.startswith("int") else wh / 1000.0
    if "harmonic" in lname:
        return 2.5 + jitter
    if "powerfactor" in lname:
        return 0.985
    if "frequency" in lname:
        return 50.0 + random.uniform(-0.02, 0.02)
    if "voltage" in lname:
        return (231.0 if "neutral" in lname else 400.2) + jitter
    if "current" in lname:
        return (0.4 if lname.startswith("neutral") else 12.1) + jitter
    if "reactive_power" in lname:
        return 0.45 + jitter
    if "apparent_power" in lname:
        return 2.7 + jitter
    if "power" in lname:
        return 2.6 + jitter
    return 1.0 + jitter


def encode_register(fmt: str, num_registers: int, value, not_available: bool = False) -> bytes:
    fmt = fmt.lower()
    size = num_registers * 2
    if fmt.startswith("str"):
        text = "" if not_available else str(value)
        return text.encode("ascii", errors="ignore")[:size].ljust(size, b"\x00")
    struct_fmt = _STRUCT[fmt]
    if not_available:
        value = float("nan") if fmt.startswith("float") else _INT_NA[fmt]
    elif not fmt.startswith("float"):
        value = int(value)
    return struct.pack(struct_fmt, value)


def build_register_image(slave_id: int, identity: dict, tick: int, na_registers=()) -> dict:
    """Return {first_register (1-based): bytes} for all point and identity registers."""
    meter_map = load_meter_map(identity["type"])
    image = {}
    for reg_str, spec in meter_map.items():
        if reg_str == "system" or not isinstance(spec, dict):
            continue
        reg = int(reg_str)
        fmt = spec["format"]
        value = plausible_value(spec["dbo_name"], fmt, slave_id, tick)
        image[reg] = encode_register(fmt, int(spec["number_of_registers"]), value, reg in na_registers)
    for reg_str, spec in (meter_map.get("system") or {}).items():
        value = identity.get(spec["dbo_name"])
        if value is None:
            continue
        reg = int(reg_str)
        image[reg] = encode_register(
            spec["format"], int(spec["number_of_registers"]), value, reg in na_registers
        )
    return image


def group_blocks(image: dict) -> list:
    """Group registers into request blocks like a polling master would (start, quantity)."""
    spans = sorted((reg, reg + len(data) // 2 - 1) for reg, data in image.items())
    blocks = []
    for first, last in spans:
        if blocks and first - blocks[-1][1] <= MAX_BLOCK_GAP and last - blocks[-1][0] < MAX_BLOCK_REGISTERS:
            blocks[-1][1] = max(blocks[-1][1], last)
        else:
            blocks.append([first, last])
    return [(first, last - first + 1) for first, last in blocks]


def build_slave_frames(slave_id: int, tick: int, identity=None, na_registers=(), fail_registers=()) -> list:
    """Build FC03 RTU (request, response) pairs covering every register in the meter map."""
    identity = identity or DEFAULT_IDENTITIES[slave_id]
    image = build_register_image(slave_id, identity, tick, na_registers)
    frames = []
    for first, qty in group_blocks(image):
        pdu_start = first - 1
        request = append_modbus_crc16(struct.pack(">BBHH", slave_id, 3, pdu_start, qty))
        if any(first <= reg < first + qty for reg in fail_registers):
            response = append_modbus_crc16(struct.pack(">BBB", slave_id, 0x83, 0x02))
        else:
            buf = bytearray(qty * 2)
            for reg, data in image.items():
                if first <= reg < first + qty:
                    offset = (reg - first) * 2
                    buf[offset:offset + len(data)] = data
            response = append_modbus_crc16(struct.pack(">BBB", slave_id, 3, qty * 2) + bytes(buf))
        frames.append((request, response))
    return frames


def _parse_pairs(values) -> dict:
    pairs = {}
    for item in values or []:
        slave, _, reg = item.partition(":")
        pairs.setdefault(int(slave), set()).add(int(reg))
    return pairs


def main():
    parser = argparse.ArgumentParser(description="Synthetic MXcloudgate Modbus RTU publisher")
    parser.add_argument("--host", default="127.0.0.1", help="Internal MQTT broker host")
    parser.add_argument("--port", type=int, default=1883, help="Internal MQTT broker port")
    parser.add_argument("--topic", default="MXcloudgate", help="Internal MQTT topic")
    parser.add_argument("--slaves", default="1,2,3", help="Comma-separated Modbus slave IDs")
    parser.add_argument("--interval", type=float, default=2.0, help="Publish interval in seconds")
    parser.add_argument("--identity-file", help="JSON file overriding DEFAULT_IDENTITIES by slave id")
    parser.add_argument("--na", action="append", metavar="SLAVE:REG", help="Report register as N/A")
    parser.add_argument(
        "--fail-block", action="append", metavar="SLAVE:REG",
        help="Answer the block containing REG with Modbus exception 0x02",
    )
    args = parser.parse_args()

    identities = dict(DEFAULT_IDENTITIES)
    if args.identity_file:
        with open(args.identity_file, "r", encoding="utf-8") as fh:
            identities.update({int(k): v for k, v in json.load(fh).items()})
    na_map = _parse_pairs(args.na)
    fail_map = _parse_pairs(args.fail_block)
    slave_ids = [int(s.strip()) for s in args.slaves.split(",") if s.strip()]
    running = True

    def _stop(_sig, _frm):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    client = (
        mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
        if hasattr(mqtt, "CallbackAPIVersion")
        else mqtt.Client()
    )
    client.connect(args.host, args.port, 60)
    client.loop_start()

    tick = 0
    try:
        while running:
            tick += 1
            for sid in slave_ids:
                frames = build_slave_frames(
                    sid, tick, identities[sid], na_map.get(sid, ()), fail_map.get(sid, ())
                )
                for req, resp in frames:
                    msg = json.dumps({"rtu_request": req.hex(), "rtu_response": resp.hex()})
                    client.publish(args.topic, msg, qos=0)
            time.sleep(args.interval)
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
