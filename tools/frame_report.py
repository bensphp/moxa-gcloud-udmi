#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Pre-deployment check of Modbus traffic (MXcloudgate broker, capture file, direct TCP, or serial RTU).

Run it on the gateway before switching to this version. It only reads telemetry and publishes
nothing to the cloud:

    python3 tools/frame_report.py -c resources/config-google-gateway.json --live 120 --save frames.jsonl
    python3 tools/frame_report.py -c resources/config-google-gateway.json --poll-tcp 10 --save frames.jsonl
    python3 tools/frame_report.py -c resources/config-google-gateway.json --poll-serial 10 --save frames.jsonl
    python3 tools/frame_report.py -c resources/config-google-gateway.json frames.jsonl

A capture file is either this tool's `--save` output (one MXcloudgate JSON message per line) or the
output of `mosquitto_sub -v -t MXcloudgate`.

Exit status: 0 = ready, 1 = problems found (listed in the report), 2 = usage or configuration error.
"""

import argparse
import json
import logging
import math
import queue
import socket
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from google_iot_core_gateway.modbus_gw.modbus_rtu_poller import (  # noqa: E402
    ModbusRTUPoller,
    resolve_serial_device,
)
from google_iot_core_gateway.modbus_gw.modbus_tcp_poller import (  # noqa: E402
    build_modbus_tcp_read_request,
    read_modbus_tcp_response,
)
from google_iot_core_gateway.modbus_gw.modbus_to_json import (  # noqa: E402
    append_modbus_crc16,
    modbus_to_json,
    verify_modbus_crc16,
)
from google_iot_core_gateway.udmi_handler.udmi_handler import (  # noqa: E402
    _FORMAT_TO_MODBUS_TYPE,
    _MODBUS_READ_FCS,
    _MODBUS_TYPE_SPECS,
    group_fc_register_spans,
    parse_modbus_ref,
)

IDENTITY_FIELDS = ("serial_no", "firmware_version", "model_name", "manufacturer_name")
# One example per kind, to compare with the meter's own display (catches register offset errors).
SAMPLE_KINDS = ("voltage", "current", "frequency", "power")
EXIT_READY, EXIT_PROBLEMS, EXIT_USAGE = 0, 1, 2


class ReportError(Exception):
    """Usage or configuration error (exit status 2)."""


class _StaticPlanAdapter:
    """Minimal UDMIHandler-compatible adapter supplying a pre-computed poll plan."""

    def __init__(self, plan):
        self._plan = plan

    def get_poll_plan(self, _mode, poll_interval_sec=10.0):
        del poll_interval_sec
        return self._plan


def load_gateway_config(path):
    """Return (meters {slave_id: {'device', 'type', 'port'}}, resources_dir, internal_broker, modbus)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ReportError(f"cannot read configuration '{path}': {exc}") from exc
    if not isinstance(cfg, dict):
        raise ReportError(f"configuration '{path}' must be a JSON object")

    site_details = cfg.get("site_details")
    if site_details is None:
        site_details = {}
    if not isinstance(site_details, dict):
        raise ReportError("site_details must be a JSON object")

    proxy_ids = site_details.get("proxy_ids")
    if proxy_ids is None:
        proxy_ids = {}
    if not isinstance(proxy_ids, dict):
        raise ReportError("site_details.proxy_ids must be a JSON object")

    meters = {}
    for device_id, spec in proxy_ids.items():
        if not isinstance(spec, dict):
            raise ReportError(f"site_details.proxy_ids.{device_id} must be an object")
        slave_raw = spec.get("modbus_slave_id")
        if isinstance(slave_raw, bool) or not isinstance(slave_raw, int):
            raise ReportError(
                f"site_details.proxy_ids.{device_id} needs 'type' and integer 'modbus_slave_id'"
            )
        meter_type = spec.get("type")
        if not isinstance(meter_type, str) or not meter_type.strip():
            raise ReportError(f"site_details.proxy_ids.{device_id} needs 'type' and 'modbus_slave_id'")
        meters[slave_raw] = {
            "device": str(device_id),
            "type": meter_type,
            "port": spec.get("port"),
        }
    if not meters:
        raise ReportError("site_details.proxy_ids lists no meters")

    env_setup = cfg.get("environment_setup")
    env_setup = env_setup if isinstance(env_setup, dict) else {}
    resources = env_setup.get("resources_path") or str(REPO_ROOT / "resources")
    internal_broker = cfg.get("internal_broker")
    internal_broker = internal_broker if isinstance(internal_broker, dict) else {}
    modbus_cfg = cfg.get("modbus")
    modbus_cfg = modbus_cfg if isinstance(modbus_cfg, dict) else {}
    return meters, Path(resources), internal_broker, modbus_cfg


def _load_site_model_path(config_path):
    """Read optional `environment_setup.udmi_site_model_path` from gateway config JSON."""
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(cfg, dict):
        return None
    env_setup = cfg.get("environment_setup")
    if not isinstance(env_setup, dict):
        return None
    raw_path = env_setup.get("udmi_site_model_path")
    if isinstance(raw_path, str) and raw_path.strip():
        return Path(raw_path.strip())
    return None


def load_register_maps(resources_dir, meter_types):
    maps = {}
    for meter_type in sorted(set(meter_types)):
        if str(meter_type).lower() in ("generic", "modbus"):
            maps[meter_type] = {}
            continue
        path = Path(resources_dir) / "modbus_dbo_maps" / f"{meter_type}.json"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ReportError(f"cannot read register map '{path}': {exc}") from exc
        if not isinstance(loaded, dict):
            raise ReportError(f"register map '{path}' must be a JSON object")
        maps[meter_type] = loaded
    return maps


def _parse_reg_key(reg_key, spec):
    text = str(reg_key)
    if ":" in text:
        fc_part, _sep, reg_part = text.partition(":")
        try:
            return int(fc_part), int(reg_part)
        except ValueError:
            return None, None
    try:
        reg_int = int(text)
    except ValueError:
        return None, None
    return int(spec.get("fc", 3)), reg_int


def _load_device_site_specs(site_model_dir, meters, maps):
    """
    Resolve per-device poll targets and expected points from `<site_model>/devices/<id>/metadata.json`
    when available, returning `(site_points_by_slave, enriched_maps)`.
    """
    enriched_maps = {key: dict(val) for key, val in maps.items()}
    site_points_by_slave = {}
    if site_model_dir is None:
        return site_points_by_slave, enriched_maps

    for slave_id, meter in meters.items():
        device_id = meter["device"]
        meta_path = Path(site_model_dir) / "devices" / device_id / "metadata.json"
        if not meta_path.is_file():
            continue
        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ReportError(f"cannot read metadata '{meta_path}': {exc}") from exc
        if not isinstance(meta, dict):
            continue

        ps_block = meta.get("pointset")
        if not isinstance(ps_block, dict) or not isinstance(ps_block.get("points"), dict):
            continue

        ln_modbus = ((meta.get("localnet") or {}).get("families") or {}).get("modbus")
        ln_modbus = ln_modbus if isinstance(ln_modbus, dict) else {}
        meta_target = (meta.get("gateway") or {}).get("target")
        meta_target = meta_target if isinstance(meta_target, dict) else {}
        meta_unit = ln_modbus.get("unitid")
        if meta_unit is None or str(meta_unit) == "":
            meta_unit = meta_target.get("unitid")
        unit_in_context = meta_unit is not None and str(meta_unit) != ""

        base_map = maps[meter["type"]]
        known_by_name = {}
        known_by_reg = {}
        for raw_key, spec in base_map.items():
            if raw_key == "system" or not isinstance(spec, dict) or "number_of_registers" not in spec:
                continue
            reg_fc, reg_int = _parse_reg_key(raw_key, spec)
            if reg_int is None:
                continue
            fmt = str(spec.get("format", "")).lower()
            entry = {
                "fc": reg_fc,
                "register": reg_int,
                "count": int(spec["number_of_registers"]),
                "name": str(spec.get("dbo_name") or raw_key),
                "units": str(spec.get("units") or ""),
                "format": fmt,
            }
            known_by_reg[reg_int] = entry
            if spec.get("dbo_name"):
                known_by_name[str(spec["dbo_name"])] = entry

        synthetic_key = f"__report_{slave_id}_{meter['type']}"
        merged_map = dict(base_map)
        resolved_points = []

        for pt_name, pt_cfg in ps_block["points"].items():
            pt_cfg = pt_cfg if isinstance(pt_cfg, dict) else {}
            ref_val = pt_cfg.get("ref")
            if ref_val is None or not str(ref_val).strip():
                known = known_by_name.get(str(pt_name))
                if known is not None:
                    resolved_points.append(dict(known, name=str(pt_name)))
                continue

            try:
                parsed = parse_modbus_ref(str(ref_val), unit_from_context=unit_in_context)
            except ValueError as exc:
                raise ReportError(f"{device_id}.pointset.points.{pt_name}: invalid ref '{ref_val}': {exc}") from exc

            reg_addr = parsed["address"]
            if parsed["legacy"]:
                known = known_by_reg.get(reg_addr)
                if known is not None:
                    resolved_points.append(dict(known, name=str(pt_name)))
                continue

            req_fc = parsed["fc"]
            if req_fc not in _MODBUS_READ_FCS:
                continue
            known = known_by_reg.get(reg_addr)
            if known is not None and known["fc"] == req_fc:
                resolved_points.append(dict(known, name=str(pt_name)))
                continue

            mod_type = parsed["params"].get("type")
            qty = parsed["quantity"]
            if qty is None and mod_type in _MODBUS_TYPE_SPECS:
                qty = _MODBUS_TYPE_SPECS[mod_type][1]
            if qty is None and known is not None:
                qty = known["count"]
            if qty is None:
                qty = 1

            if mod_type in _MODBUS_TYPE_SPECS:
                fmt = _MODBUS_TYPE_SPECS[mod_type][0]
            elif known is not None:
                fmt = known["format"]
            else:
                fmt = _FORMAT_TO_MODBUS_TYPE.get("uint16", "uint16").lower()

            resolved_points.append(
                {
                    "fc": req_fc,
                    "register": reg_addr,
                    "count": int(qty),
                    "name": str(pt_name),
                    "units": str(pt_cfg.get("units") or (known["units"] if known else "")),
                    "format": fmt,
                }
            )
            map_key = f"{req_fc}:{reg_addr}"
            if map_key not in merged_map:
                merged_map[map_key] = {
                    "dbo_name": str(pt_name),
                    "number_of_registers": int(qty),
                    "format": fmt,
                    "units": str(pt_cfg.get("units") or "No-units"),
                    "fc": int(req_fc),
                }

        enriched_maps[synthetic_key] = merged_map
        meter["decoder_type"] = synthetic_key
        site_points_by_slave[slave_id] = resolved_points

    return site_points_by_slave, enriched_maps


def build_poll_plan(meters, maps, site_points_by_slave=None):
    """Derive grouped [(fc, start, qty)] spans per meter from site points + system identity regs."""
    site_points_by_slave = site_points_by_slave or {}
    plan = []
    for slave_id, meter in sorted(meters.items()):
        register_map = maps[meter["type"]]
        fc_spans = []
        if slave_id in site_points_by_slave:
            for pt_spec in site_points_by_slave[slave_id]:
                fc_spans.append((int(pt_spec["fc"]), int(pt_spec["register"]), int(pt_spec["count"])))
        else:
            for raw_key, spec in register_map.items():
                if raw_key == "system" or not isinstance(spec, dict) or "number_of_registers" not in spec:
                    continue
                reg_fc, reg_int = _parse_reg_key(raw_key, spec)
                if reg_int is not None:
                    fc_spans.append((reg_fc, reg_int, int(spec["number_of_registers"])))

        sys_map = register_map.get("system") or {}
        if isinstance(sys_map, dict):
            for raw_key, spec in sys_map.items():
                if not isinstance(spec, dict) or "number_of_registers" not in spec:
                    continue
                reg_fc, reg_int = _parse_reg_key(raw_key, spec)
                if reg_int is not None:
                    fc_spans.append((reg_fc, reg_int, int(spec["number_of_registers"])))

        blocks = group_fc_register_spans(sorted(set(fc_spans)))
        if blocks:
            plan.append(
                {
                    "device_id": meter["device"],
                    "slave_id": slave_id,
                    "port": meter.get("port"),
                    "blocks": blocks,
                }
            )
    return plan


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
        if not isinstance(msg, dict):
            return None
        return bytes.fromhex(msg["rtu_request"]), bytes.fromhex(msg["rtu_response"])
    except (ValueError, KeyError, TypeError):
        return None


def _spans(register_map, section=None):
    """{(fc, register): (number_of_registers, dbo_name, units)} for points or `system` section."""
    source = (register_map.get("system") or {}) if section == "system" else register_map
    spans = {}
    for reg, spec in source.items():
        if reg == "system" or not isinstance(spec, dict) or "number_of_registers" not in spec:
            continue
        reg_fc, reg_int = _parse_reg_key(reg, spec)
        if reg_int is None:
            continue
        spans[(reg_fc, reg_int)] = (
            int(spec["number_of_registers"]),
            spec.get("dbo_name", str(reg_int)),
            spec.get("units", ""),
        )
    return spans


def _covered(covered_fc, fc, reg, count):
    return all((fc, addr) in covered_fc for addr in range(reg, reg + count))


def analyse(messages, meters, maps, site_points_by_slave=None):
    """Analyse raw MXcloudgate messages; returns a report dict (see render())."""
    site_points_by_slave = site_points_by_slave or {}
    slave_to_type = {slave: meter.get("decoder_type", meter["type"]) for slave, meter in meters.items()}
    totals = Counter()
    slaves = defaultdict(lambda: {
        "frames": 0, "ok": 0, "errors": Counter(), "rejected_blocks": set(), "blocks": set(),
        "covered": set(), "fc_covered": set(), "values": {}, "fc_values": {}, "unavailable": set(),
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
        payload_fc = int(payload.get("fc") or request[1])
        if payload.get("error"):
            info["errors"][payload["error"]] += 1
            if payload.get("error_kind") == "exception":
                info["rejected_blocks"].add(block)
            continue
        info["ok"] += 1
        info["blocks"].add(block)
        reg_range = range(block[0], block[0] + block[1])
        info["covered"].update(reg_range)
        info["fc_covered"].update((payload_fc, addr) for addr in reg_range)
        data_items = payload.get("data") or {}
        info["values"].update(data_items)
        for reg_key, reg_val in data_items.items():
            info["fc_values"][(payload_fc, str(reg_key))] = reg_val
        info["unavailable"].update(payload.get("unavailable") or {})

    report = {"totals": totals, "meters": {}, "unknown_slaves": {}}
    for slave, info in sorted(slaves.items()):
        if slave not in meters:
            report["unknown_slaves"][slave] = info["frames"]
    for slave, meter in sorted(meters.items()):
        info = slaves[slave]
        register_map = maps[meter["type"]]
        identity = {}
        for (reg_fc, reg), (count, name, _units) in sorted(_spans(register_map, "system").items()):
            if name in IDENTITY_FIELDS:
                val = info["fc_values"].get((reg_fc, str(reg)), info["values"].get(str(reg)))
                identity[name] = {
                    "register": reg,
                    "count": count,
                    "polled": _covered(info["fc_covered"], reg_fc, reg, count),
                    "value": val,
                }
        if slave in site_points_by_slave:
            expected_points = [
                (int(spec["fc"]), int(spec["register"]), int(spec["count"]), spec["name"], spec.get("units", ""))
                for spec in site_points_by_slave[slave]
            ]
        else:
            expected_points = [
                (reg_fc, reg, count, name, units)
                for (reg_fc, reg), (count, name, units) in sorted(_spans(register_map).items())
            ]
        missing = sorted(
            name
            for reg_fc, reg, count, name, _units in expected_points
            if not _covered(info["fc_covered"], reg_fc, reg, count)
        )
        samples = []
        for kind in SAMPLE_KINDS:
            for reg_fc, reg, _count, name, units in expected_points:
                has_val = (reg_fc, str(reg)) in info["fc_values"] or (
                    reg_fc == 3 and str(reg) in info["values"]
                )
                if kind in name.lower() and has_val:
                    val = info["fc_values"].get(
                        (reg_fc, str(reg)), info["values"].get(str(reg)) if reg_fc == 3 else None
                    )
                    samples.append((name, val, units))
                    break
        report["meters"][slave] = {
            **meter,
            "frames": info["frames"],
            "ok": info["ok"],
            "errors": dict(info["errors"]),
            "rejected_blocks": sorted(info["rejected_blocks"]),
            "blocks": sorted(info["blocks"]),
            "identity": identity,
            "points_total": len(expected_points),
            "points_missing": missing,
            "unavailable": sorted(info["unavailable"], key=int),
            "samples": samples,
            "generic": (not register_map) and (slave not in site_points_by_slave),
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
        if meter.get("generic"):
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
        if meter.get("generic"):
            lines.append("  generic Modbus device (points configured via UDMI config)")
        else:
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
        lines.extend(f"- {problem}" for problem in problems)
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
        topic=broker.get("topic") or "MXcloudgate",
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


def _cfg_int(cfg, key, default):
    val = cfg.get(key)
    if val is None:
        return default
    if isinstance(val, bool) or not isinstance(val, int):
        raise ReportError(f"modbus.{key} must be an integer")
    return val


def _cfg_float(cfg, key, default):
    val = cfg.get(key)
    if val is None:
        return default
    if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
        raise ReportError(f"modbus.{key} must be a finite number")
    return float(val)


def _cfg_bool(cfg, key, default=False):
    val = cfg.get(key)
    if val is None:
        return default
    if not isinstance(val, bool):
        raise ReportError(f"modbus.{key} must be a boolean")
    return val


def capture_poll_tcp(seconds, modbus_cfg, plan, logger):
    """Poll Modbus TCP directly for `seconds` and return JSON lines `{"rtu_request": ..., "rtu_response": ...}`."""
    host = str(modbus_cfg.get("poll_host") or "127.0.0.1")
    port = _cfg_int(modbus_cfg, "poll_port", 502)
    timeout_sec = max(0.1, _cfg_float(modbus_cfg, "poll_timeout_sec", 2.0))
    interval_sec = max(0.05, _cfg_float(modbus_cfg, "poll_interval_sec", 1.0))

    messages = []
    deadline = time.monotonic() + seconds
    tx_id = 0
    sock = None
    try:
        while True:
            for target in plan:
                slave_id = target["slave_id"]
                for fc, start_reg, qty in target["blocks"]:
                    tx_id = (tx_id + 1) & 0xFFFF or 1
                    try:
                        adu = build_modbus_tcp_read_request(tx_id, slave_id, fc, start_reg, qty)
                        if sock is None:
                            sock = socket.create_connection((host, port), timeout=timeout_sec)
                            sock.settimeout(timeout_sec)
                        sock.sendall(adu)
                        resp_body = read_modbus_tcp_response(sock, tx_id, slave_id)
                    except (OSError, ValueError) as exc:
                        logger.warning(
                            "Modbus TCP poll failed (%s:%s unit %s fc %s %s+%s): %s",
                            host,
                            port,
                            slave_id,
                            fc,
                            start_reg,
                            qty,
                            exc,
                        )
                        if sock is not None:
                            try:
                                sock.close()
                            except OSError:
                                pass
                            sock = None
                        continue
                    rtu_req = append_modbus_crc16(adu[6:])
                    rtu_resp = append_modbus_crc16(resp_body)
                    messages.append(
                        json.dumps({"rtu_request": rtu_req.hex(), "rtu_response": rtu_resp.hex()})
                    )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(interval_sec, remaining))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return messages


def capture_poll_serial(seconds, modbus_cfg, plan, logger):
    """Poll Modbus RTU directly over serial/RS-485 for `seconds` and return JSON frame lines."""
    default_port = modbus_cfg.get("serial_port")
    serial_ports = modbus_cfg.get("serial_ports") or {}
    if not isinstance(serial_ports, dict):
        raise ReportError("modbus.serial_ports must be a JSON object")

    for target in plan:
        try:
            resolve_serial_device(
                target.get("port"),
                serial_ports_map=serial_ports,
                default_port=default_port,
            )
        except ValueError as exc:
            raise ReportError(
                f"{target['device_id']} (unit {target['slave_id']}): {exc}"
            ) from exc

    timeout_sec = max(0.1, _cfg_float(modbus_cfg, "poll_timeout_sec", 2.0))
    interval_sec = max(0.05, _cfg_float(modbus_cfg, "poll_interval_sec", 1.0))
    baudrate = _cfg_int(modbus_cfg, "baudrate", 9600)
    bytesize = _cfg_int(modbus_cfg, "bytesize", 8)
    raw_parity = modbus_cfg.get("parity") if modbus_cfg.get("parity") is not None else "N"
    if not isinstance(raw_parity, str):
        raise ReportError("modbus.parity must be a string")
    parity = raw_parity.strip().upper()
    stopbits = _cfg_int(modbus_cfg, "stopbits", 1)
    rs485_mode = _cfg_bool(modbus_cfg, "rs485_mode", False)

    inbox = queue.Queue(maxsize=100000)
    adapter = _StaticPlanAdapter(plan)
    try:
        poller = ModbusRTUPoller(
            logger,
            inbox,
            adapter,
            mode="active",
            interval_sec=interval_sec,
            timeout_sec=timeout_sec,
            default_port=default_port,
            serial_ports=serial_ports,
            baudrate=baudrate,
            bytesize=bytesize,
            parity=parity,
            stopbits=stopbits,
            rs485_mode=rs485_mode,
        )
    except ValueError as exc:
        raise ReportError(str(exc)) from exc

    messages = []
    deadline = time.monotonic() + seconds
    try:
        while True:
            poller.poll_once()
            while not inbox.empty():
                messages.append(inbox.get_nowait())
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(interval_sec, remaining))
    finally:
        poller.stop()
    while not inbox.empty():
        messages.append(inbox.get_nowait())
    return messages


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("-c", "--config", required=True, help="Gateway configuration (config-google-gateway.json)")
    parser.add_argument("capture", nargs="?", help="Capture file (--save output or mosquitto_sub -v output)")
    parser.add_argument("--live", type=float, metavar="SECONDS", help="Listen to the internal broker instead")
    parser.add_argument("--poll-tcp", type=float, metavar="SECONDS", help="Poll Modbus TCP directly instead")
    parser.add_argument("--poll-serial", type=float, metavar="SECONDS", help="Poll Modbus RTU serial directly instead")
    parser.add_argument("--site-model", metavar="PATH", help="Optional UDMI site model path override for point spans")
    parser.add_argument(
        "--save",
        metavar="FILE",
        help="With --live, --poll-tcp, or --poll-serial: also write the captured messages to FILE",
    )
    args = parser.parse_args(argv)

    source_count = sum(
        [
            args.capture is not None,
            args.live is not None,
            args.poll_tcp is not None,
            args.poll_serial is not None,
        ]
    )
    if source_count != 1:
        parser.error("give exactly one of a capture file, --live SECONDS, --poll-tcp SECONDS, or --poll-serial SECONDS")
    if args.save and args.capture is not None:
        parser.error("--save needs --live, --poll-tcp, or --poll-serial")
    for flag_name, duration in (
        ("--live", args.live),
        ("--poll-tcp", args.poll_tcp),
        ("--poll-serial", args.poll_serial),
    ):
        if duration is not None and duration <= 0:
            parser.error(f"{flag_name} SECONDS must be > 0")

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    report_logger = logging.getLogger("frame_report")
    try:
        meters, resources_dir, broker, modbus_cfg = load_gateway_config(args.config)
        maps = load_register_maps(resources_dir, [meter["type"] for meter in meters.values()])
        site_model_dir = Path(args.site_model) if args.site_model else _load_site_model_path(args.config)
        site_points_by_slave, maps = _load_device_site_specs(site_model_dir, meters, maps)

        if args.live is not None:
            print(f"Listening for {args.live:.1f} s ...", file=sys.stderr)
            messages = capture_live(args.live, broker, report_logger)
        elif args.poll_tcp is not None:
            print(f"Polling Modbus TCP for {args.poll_tcp:.1f} s ...", file=sys.stderr)
            plan = build_poll_plan(meters, maps, site_points_by_slave=site_points_by_slave)
            messages = capture_poll_tcp(args.poll_tcp, modbus_cfg, plan, report_logger)
        elif args.poll_serial is not None:
            print(f"Polling Modbus RTU serial for {args.poll_serial:.1f} s ...", file=sys.stderr)
            plan = build_poll_plan(meters, maps, site_points_by_slave=site_points_by_slave)
            messages = capture_poll_serial(args.poll_serial, modbus_cfg, plan, report_logger)
        else:
            try:
                with open(args.capture, "r", encoding="utf-8", errors="replace") as fh:
                    messages = fh.readlines()
            except OSError as exc:
                raise ReportError(f"cannot read capture '{args.capture}': {exc}") from exc

        if args.save and args.capture is None:
            with open(args.save, "w", encoding="utf-8") as fh:
                fh.writelines(msg.strip() + "\n" for msg in messages)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = analyse(messages, meters, maps, site_points_by_slave=site_points_by_slave)
    problems = problems_of(report)
    print(render(report, problems))
    return EXIT_PROBLEMS if problems else EXIT_READY


if __name__ == "__main__":
    sys.exit(main())
