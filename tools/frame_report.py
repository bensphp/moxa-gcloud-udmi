#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Pre-deployment check of real MXcloudgate traffic: CRCs, polled registers, meter identity.

Run it on the gateway before switching to this version. It only listens and publishes nothing,
so it is safe next to a running gateway:

    python3 tools/frame_report.py -c resources/config-google-gateway.json --live 120 --save frames.jsonl
    python3 tools/frame_report.py -c resources/config-google-gateway.json frames.jsonl

A capture file is either this tool's `--save` output (one MXcloudgate JSON message per line) or the
output of `mosquitto_sub -v -t MXcloudgate`.

Exit status: 0 = ready, 1 = problems found (listed in the report), 2 = usage or configuration error.
"""

import argparse
import json
import logging
import queue
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from google_iot_core_gateway.modbus_gw.modbus_to_json import (  # noqa: E402
    modbus_to_json,
    verify_modbus_crc16,
)

IDENTITY_FIELDS = ("serial_no", "firmware_version", "model_name", "manufacturer_name")
# One example per kind, to compare with the meter's own display (catches register offset errors).
SAMPLE_KINDS = ("voltage", "current", "frequency", "power")
EXIT_READY, EXIT_PROBLEMS, EXIT_USAGE = 0, 1, 2


class ReportError(Exception):
    """Usage or configuration error (exit status 2)."""


def load_gateway_config(path):
    """Return (meters {slave_id: {"device", "type"}}, resources_dir, internal_broker settings)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ReportError(f"cannot read configuration '{path}': {exc}") from exc
    meters = {}
    for device_id, spec in ((cfg.get("site_details") or {}).get("proxy_ids") or {}).items():
        try:
            meters[int(spec["modbus_slave_id"])] = {"device": str(device_id), "type": str(spec["type"])}
        except (KeyError, TypeError, ValueError) as exc:
            raise ReportError(f"site_details.proxy_ids.{device_id} needs 'type' and 'modbus_slave_id'") from exc
    if not meters:
        raise ReportError("site_details.proxy_ids lists no meters")
    resources = (cfg.get("environment_setup") or {}).get("resources_path") or str(REPO_ROOT / "resources")
    return meters, Path(resources), cfg.get("internal_broker") or {}


def load_register_maps(resources_dir, meter_types):
    maps = {}
    for meter_type in sorted(set(meter_types)):
        path = Path(resources_dir) / "modbus_dbo_maps" / f"{meter_type}.json"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                maps[meter_type] = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ReportError(f"cannot read register map '{path}': {exc}") from exc
    return maps


def parse_message(text):
    """Return (request, response) bytes from an MXcloudgate message or a `mosquitto_sub -v` line."""
    text = text.strip()
    if not text:
        return None
    if not text.startswith("{"):
        parts = text.split(None, 1)  # "<topic> <payload>"
        if len(parts) != 2:
            return None
        text = parts[1]
    try:
        msg = json.loads(text)
        return bytes.fromhex(msg["rtu_request"]), bytes.fromhex(msg["rtu_response"])
    except (ValueError, KeyError, TypeError):
        return None


def _spans(register_map, section=None):
    """{register: (number_of_registers, dbo_name, units)} for points, or for the `system` section."""
    source = (register_map.get("system") or {}) if section == "system" else register_map
    spans = {}
    for reg, spec in source.items():
        if reg == "system" or not isinstance(spec, dict) or "number_of_registers" not in spec:
            continue
        spans[int(reg)] = (int(spec["number_of_registers"]), spec.get("dbo_name", reg), spec.get("units", ""))
    return spans


def _covered(covered, reg, count):
    return all(r in covered for r in range(reg, reg + count))


def analyse(messages, meters, maps):
    """Analyse raw MXcloudgate messages; returns a report dict (see render())."""
    slave_to_type = {slave: m["type"] for slave, m in meters.items()}
    totals = Counter()
    slaves = defaultdict(lambda: {
        "frames": 0, "ok": 0, "errors": Counter(), "rejected_blocks": set(), "blocks": set(),
        "covered": set(), "values": {}, "unavailable": set(),
    })
    for text in messages:
        frame = parse_message(text)
        if frame is None:
            totals["unparseable"] += 1
            continue
        request, response = frame
        totals["frames"] += 1
        if len(request) == 8:
            totals["request_crc_ok" if verify_modbus_crc16(request) else "request_crc_bad"] += 1
        elif len(request) == 6:
            totals["request_without_crc"] += 1
        if len(response) >= 5:
            totals["response_crc_ok" if verify_modbus_crc16(response) else "response_crc_bad"] += 1
        if len(request) < 6 or request[1] not in (3, 4):
            totals["other_function"] += 1
            continue
        slave = request[0]
        info = slaves[slave]
        info["frames"] += 1
        if slave not in meters:
            continue
        decoded = modbus_to_json(request, response, slave_to_type=slave_to_type, dbo_maps=maps, strict_crc=True)
        if not decoded:
            info["errors"]["not decoded"] += 1
            continue
        payload = json.loads(decoded)
        block = (payload["start_register"], payload["quantity"])
        if payload.get("error"):
            info["errors"][payload["error"]] += 1
            if payload.get("error_kind") == "exception":
                info["rejected_blocks"].add(block)
            continue
        info["ok"] += 1
        info["blocks"].add(block)
        info["covered"].update(range(block[0], block[0] + block[1]))
        info["values"].update(payload.get("data") or {})
        info["unavailable"].update(payload.get("unavailable") or {})

    report = {"totals": totals, "meters": {}, "unknown_slaves": {}}
    for slave, info in sorted(slaves.items()):
        if slave not in meters:
            report["unknown_slaves"][slave] = info["frames"]
    for slave, meter in sorted(meters.items()):
        info = slaves[slave]
        register_map = maps[meter["type"]]
        identity = {}
        for reg, (count, name, _units) in sorted(_spans(register_map, "system").items()):
            if name in IDENTITY_FIELDS:
                identity[name] = {
                    "register": reg, "count": count, "polled": _covered(info["covered"], reg, count),
                    "value": info["values"].get(str(reg)),
                }
        points = _spans(register_map)
        missing = sorted(name for reg, (count, name, _u) in points.items() if not _covered(info["covered"], reg, count))
        samples = []
        for kind in SAMPLE_KINDS:
            for reg, (_count, name, units) in sorted(points.items()):
                if kind in name.lower() and str(reg) in info["values"]:
                    samples.append((name, info["values"][str(reg)], units))
                    break
        report["meters"][slave] = {
            **meter, "frames": info["frames"], "ok": info["ok"], "errors": dict(info["errors"]),
            "rejected_blocks": sorted(info["rejected_blocks"]), "blocks": sorted(info["blocks"]),
            "identity": identity, "points_total": len(points), "points_missing": missing,
            "unavailable": sorted(info["unavailable"], key=int), "samples": samples,
        }
    return report


def problems_of(report):
    """List the findings that would hurt the deployment or the UDMI sequencer run."""
    totals = report["totals"]
    found = []
    if not totals["frames"]:
        found.append("No MXcloudgate frames were received or parsed: is MXcloudgate polling and publishing "
                     "to the configured internal broker topic?")
        return found
    bad, ok = totals["response_crc_bad"], totals["response_crc_ok"]
    if bad and not ok:
        found.append(f"Every response ({bad}) fails the Modbus CRC check: this MXcloudgate does not forward "
                     "the CRC as sent by the meter. Set modbus.crc_check to \"off\".")
    elif bad:
        found.append(f"{bad} of {bad + ok} responses fail the CRC check (the gateway drops them): check the "
                     "RS-485 wiring, termination and baud rate.")
    if totals["request_crc_bad"]:
        found.append(f"{totals['request_crc_bad']} requests have a wrong CRC (the gateway drops these frames).")
    for slave, meter in report["meters"].items():
        name = f"{meter['device']} (unit {slave}, {meter['type']})"
        if not meter["frames"]:
            found.append(f"{name}: no frames. Is MXcloudgate polling this unit id?")
            continue
        if not meter["ok"]:
            found.append(f"{name}: no frame could be decoded ({meter['errors']}).")
            continue
        missing_identity = [f"{field} ({spec['register']})" for field, spec in meter["identity"].items()
                            if not spec["polled"]]
        if missing_identity:
            found.append(f"{name}: identity registers not seen in this capture: {', '.join(missing_identity)}. "
                         "Add them to the MXcloudgate polling list (or capture longer if they are polled rarely); "
                         "without them valid_serial_no / state_make_model / state_software cannot pass.")
        if meter["points_missing"]:
            found.append(f"{name}: {len(meter['points_missing'])} of {meter['points_total']} register-map points "
                         "were not seen in this capture. Points that are never polled go to 'failure' after "
                         "modbus.stale_timeout_sec: poll them, or remove them from the site model.")
        if meter["rejected_blocks"]:
            found.append(f"{name}: the meter rejects these blocks with Modbus exceptions: "
                         f"{meter['rejected_blocks']} (register map or polling list does not match the meter).")
        if meter["unavailable"]:
            found.append(f"{name}: registers {', '.join(meter['unavailable'])} report 'not available'. If that "
                         "persists, the meter does not provide them: remove those points from the site model, "
                         "otherwise they stay in 'failure'.")
    return found


def render(report, problems):
    totals = report["totals"]
    lines = ["MXcloudgate traffic report", "=========================="]
    lines.append(f"frames: {totals['frames']}  unparseable lines: {totals['unparseable']}  "
                 f"other function codes: {totals['other_function']}")
    lines.append(f"response CRC: {totals['response_crc_ok']} ok, {totals['response_crc_bad']} bad   "
                 f"request CRC: {totals['request_crc_ok']} ok, {totals['request_crc_bad']} bad, "
                 f"{totals['request_without_crc']} without CRC")
    for slave, meter in report["meters"].items():
        lines.append("")
        lines.append(f"{meter['device']} - unit {slave} - {meter['type']}: {meter['frames']} frames, "
                     f"{meter['ok']} decoded")
        if meter["errors"]:
            lines.append(f"  errors: {meter['errors']}")
        lines.append(f"  blocks polled (start register, count): {meter['blocks']}")
        for field, spec in meter["identity"].items():
            state = f"= {spec['value']!r}" if spec["polled"] else "NOT POLLED"
            lines.append(f"  identity {field:18s} reg {spec['register']:>5}: {state}")
        lines.append(f"  points polled: {meter['points_total'] - len(meter['points_missing'])} of "
                     f"{meter['points_total']}")
        if meter["points_missing"]:
            lines.append(f"  not polled: {', '.join(meter['points_missing'])}")
        if meter["unavailable"]:
            lines.append(f"  'not available' registers: {', '.join(meter['unavailable'])}")
        for name, value, units in meter["samples"]:
            lines.append(f"  sample {name} = {value} {units}  (compare with the meter display)")
    for slave, count in report["unknown_slaves"].items():
        lines.append(f"\nunit {slave}: {count} frames but not in site_details.proxy_ids (ignored by the gateway)")
    lines.append("")
    if problems:
        lines.append("PROBLEMS")
        lines.extend(f"- {p}" for p in problems)
    else:
        lines.append("READY: CRCs valid, identity registers and all register-map points polled.")
    return "\n".join(lines)


def capture_live(seconds, broker, logger):
    """Collect raw MXcloudgate messages from the internal broker for `seconds` (listen only)."""
    from google_iot_core_gateway.internal_broker_subscriber.internal_broker_subscriber import (  # noqa: E501
        MosquittoMQTTSubscriber,
    )

    inbox = queue.Queue(maxsize=100000)
    subscriber = MosquittoMQTTSubscriber(
        logger,
        inbox,
        broker.get("mqtt_bridge_hostname") or "127.0.0.1",
        int(broker.get("mqtt_bridge_port") or 1883),
        broker.get("trusted_root_ca"),
        broker.get("x509_certificate"),
        broker.get("private_key"),
        bool(broker.get("tls_insecure_set") or False),
        bool(broker.get("enable_tls") or False),
    )
    messages = []
    subscriber.run()
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            try:
                messages.append(inbox.get(timeout=0.2))
            except queue.Empty:
                pass
    finally:
        subscriber.stop()
    while not inbox.empty():
        messages.append(inbox.get_nowait())
    return messages


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("-c", "--config", required=True, help="Gateway configuration (config-google-gateway.json)")
    parser.add_argument("capture", nargs="?", help="Capture file (--save output or mosquitto_sub -v output)")
    parser.add_argument("--live", type=float, metavar="SECONDS", help="Listen to the internal broker instead")
    parser.add_argument("--save", metavar="FILE", help="With --live: also write the captured messages to FILE")
    args = parser.parse_args(argv)
    if bool(args.capture) == bool(args.live):
        parser.error("give either a capture file or --live SECONDS")
    if args.save and not args.live:
        parser.error("--save needs --live")
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    try:
        meters, resources_dir, broker = load_gateway_config(args.config)
        maps = load_register_maps(resources_dir, [m["type"] for m in meters.values()])
        if args.live:
            print(f"Listening for {args.live:.0f} s ...", file=sys.stderr)
            messages = capture_live(args.live, broker, logging.getLogger("frame_report"))
            if args.save:
                with open(args.save, "w", encoding="utf-8") as fh:
                    fh.writelines(m.strip() + "\n" for m in messages)
        else:
            try:
                with open(args.capture, "r", encoding="utf-8", errors="replace") as fh:
                    messages = fh.readlines()
            except OSError as exc:
                raise ReportError(f"cannot read capture '{args.capture}': {exc}") from exc
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    report = analyse(messages, meters, maps)
    problems = problems_of(report)
    print(render(report, problems))
    return EXIT_PROBLEMS if problems else EXIT_READY


if __name__ == "__main__":
    sys.exit(main())
