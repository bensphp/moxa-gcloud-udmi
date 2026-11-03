#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""
Synthetic Moxa MXcloudgate Modbus RTU publisher for local testing and UDMI Sequencer validation.

Publishes CRC-16 valid Modbus FC03 request/response pairs onto the `MXcloudgate` MQTT topic
for configured Modbus slave IDs (default: 1, 2, 3 -> EM-11, EM-12, EM-13).
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

from google_iot_core_gateway.modbus_gw.modbus_to_json import append_modbus_crc16


# Realistic 3-phase 230V/400V 50Hz Schneider PowerLogic register values (1-based addresses)
FLOAT32_BASE_VALUES = {
    3000: 12.4,   # line1_current_sensor
    3002: 11.9,   # line2_current_sensor
    3004: 12.1,   # line3_current_sensor
    3006: 0.4,    # neutral_current_sensor
    3010: 12.13,  # average_line_current_sensor
    3020: 400.2,  # line1_line2_voltage_sensor
    3022: 399.8,  # line2_line3_voltage_sensor
    3024: 400.5,  # line1_line3_voltage_sensor
    3026: 400.17, # average_line_line_voltage_sensor
    3028: 231.1,  # line1_neutral_voltage_sensor
    3030: 230.8,  # line2_neutral_voltage_sensor
    3032: 231.2,  # line3_neutral_voltage_sensor
    3036: 231.03, # average_line_neutral_voltage_sensor
    3054: 2.72,   # line1_neutral_power_sensor
    3056: 2.61,   # line2_neutral_power_sensor
    3058: 2.66,   # line3_neutral_power_sensor
    3060: 7.99,   # total_power_sensor
    3062: 0.45,   # line1_neutral_reactive_power_sensor
    3064: 0.42,   # line2_neutral_reactive_power_sensor
    3066: 0.44,   # line3_neutral_reactive_power_sensor
    3068: 1.31,   # total_reactive_power_sensor
    3070: 2.76,   # line1_neutral_apparent_power_sensor
    3072: 2.64,   # line2_neutral_apparent_power_sensor
    3074: 2.70,   # line3_neutral_apparent_power_sensor
    3076: 8.10,   # total_apparent_power_sensor
    3078: 0.985,  # line1_neutral_powerfactor_sensor
    3080: 0.988,  # line2_neutral_powerfactor_sensor
    3082: 0.986,  # line3_neutral_powerfactor_sensor
    3084: 0.986,  # total_powerfactor_sensor
}


def build_slave_frames(slave_id: int, tick: int) -> list:
    """Build 3 FC03 RTU request/response pairs covering all 32 meter points."""
    frames = []
    jitter = (slave_id * 0.1) + random.uniform(-0.05, 0.05)

    # Block 1: PDU 2999, qty 86 (1-based registers 3000..3085)
    start1, qty1 = 2999, 86
    buf1 = bytearray(qty1 * 2)
    for reg_1based, base_val in FLOAT32_BASE_VALUES.items():
        offset = (reg_1based - 1 - start1) * 2
        val = base_val if reg_1based >= 3078 else (base_val + jitter)
        buf1[offset:offset + 4] = struct.pack(">f", val)
    req1 = append_modbus_crc16(struct.pack(">BBHH", slave_id, 3, start1, qty1))
    resp1 = append_modbus_crc16(struct.pack(">BBB", slave_id, 3, qty1 * 2) + bytes(buf1))
    frames.append((req1, resp1))

    # Block 2: PDU 3109, qty 42 (1-based register 3110 frequency + PM8240 3144..3150 powerfactors)
    start2, qty2 = 3109, 42
    buf2 = bytearray(qty2 * 2)
    buf2[0:4] = struct.pack(">f", 50.0 + random.uniform(-0.02, 0.02))
    for pf_reg, pf_val in ((3144, 0.985), (3146, 0.988), (3148, 0.986), (3150, 0.986)):
        off_pf = (pf_reg - 1 - start2) * 2
        buf2[off_pf:off_pf + 4] = struct.pack(">f", pf_val)
    req2 = append_modbus_crc16(struct.pack(">BBHH", slave_id, 3, start2, qty2))
    resp2 = append_modbus_crc16(struct.pack(">BBB", slave_id, 3, qty2 * 2) + bytes(buf2))
    frames.append((req2, resp2))

    # Block 3: PDU 3215, qty 20 (1-based registers 3216 & 3232: PM5561/PM5111 int64 energy accumulators)
    start3, qty3 = 3215, 20
    buf3 = bytearray(qty3 * 2)
    wh = 125000 + slave_id * 1000 + tick * 5
    varh = 18000 + slave_id * 200 + tick * 1
    buf3[0:8] = struct.pack(">q", wh)
    off_reactive = (3232 - 1 - start3) * 2
    buf3[off_reactive:off_reactive + 8] = struct.pack(">q", varh)
    req3 = append_modbus_crc16(struct.pack(">BBHH", slave_id, 3, start3, qty3))
    resp3 = append_modbus_crc16(struct.pack(">BBB", slave_id, 3, qty3 * 2) + bytes(buf3))
    frames.append((req3, resp3))

    # Block 4: PDU 2705, qty 10 (1-based registers 2706 & 2714: PM8240 float32 energy accumulators)
    start4, qty4 = 2705, 10
    buf4 = bytearray(qty4 * 2)
    buf4[0:4] = struct.pack(">f", float(wh) / 1000.0)
    off_reac4 = (2714 - 1 - start4) * 2
    buf4[off_reac4:off_reac4 + 4] = struct.pack(">f", float(varh) / 1000.0)
    req4 = append_modbus_crc16(struct.pack(">BBHH", slave_id, 3, start4, qty4))
    resp4 = append_modbus_crc16(struct.pack(">BBB", slave_id, 3, qty4 * 2) + bytes(buf4))
    frames.append((req4, resp4))

    return frames


def main():
    parser = argparse.ArgumentParser(description="Synthetic MXcloudgate Modbus RTU publisher")
    parser.add_argument("--host", default="127.0.0.1", help="Internal MQTT broker host")
    parser.add_argument("--port", type=int, default=1883, help="Internal MQTT broker port")
    parser.add_argument("--topic", default="MXcloudgate", help="Internal MQTT topic")
    parser.add_argument("--slaves", default="1,2,3", help="Comma-separated Modbus slave IDs")
    parser.add_argument("--interval", type=float, default=2.0, help="Publish interval in seconds")
    args = parser.parse_args()

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
                for req, resp in build_slave_frames(sid, tick):
                    msg = json.dumps({"rtu_request": req.hex(), "rtu_response": resp.hex()})
                    client.publish(args.topic, msg, qos=0)
            time.sleep(args.interval)
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
