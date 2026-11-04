# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Decode MXcloudgate Modbus RTU request/response frame pairs into register values.

Output (JSON string) for FC03/FC04 frames:

    {
      "slave_id": 1, "fc": 3,
      "start_register": 3028,   # 1-based register number of the first requested register
      "quantity": 2,            # number of requested registers
      "data": {"3028": 231.1},  # decoded values keyed by 1-based register number
      "unavailable": {"3030": "N/A(ffc00000)"},  # registers the meter reported as "not available"
      "error": null, "error_kind": null, "exception_code": null
    }

`error_kind` is one of `crc`, `framing`, `truncated`, `exception` or `transport` when the frame
could not be used; `data` is then null.
"""

import json
import logging
import math
import os
import struct

from google_iot_core_gateway import ROOT_DIR

logger = logging.getLogger(__name__)

_FILE_JSON_CACHE = {}

ERROR_CRC = "crc"
ERROR_FRAMING = "framing"
ERROR_TRUNCATED = "truncated"
ERROR_EXCEPTION = "exception"
ERROR_TRANSPORT = "transport"

MODBUS_EXCEPTION_NAMES = {
    0x01: "illegal function",
    0x02: "illegal data address",
    0x03: "illegal data value",
    0x04: "slave device failure",
    0x05: "acknowledge",
    0x06: "slave device busy",
    0x08: "memory parity error",
    0x0A: "gateway path unavailable",
    0x0B: "gateway target device failed to respond",
}

# Schneider Electric PowerLogic "not available" sentinels per register data type.
_INT_NOT_AVAILABLE = {
    "int16u": 0xFFFF,
    "uint16": 0xFFFF,
    "int16": -0x8000,
    "int16s": -0x8000,
    "int32u": 0xFFFFFFFF,
    "uint32": 0xFFFFFFFF,
    "int32": -0x80000000,
    "int32s": -0x80000000,
    "int64": -0x8000000000000000,
    "int64u": 0xFFFFFFFFFFFFFFFF,
    "uint64": 0xFFFFFFFFFFFFFFFF,
}

_STRUCT_FORMATS = {
    "float32": (">f", 4),
    "float64": (">d", 8),
    "int16u": (">H", 2),
    "uint16": (">H", 2),
    "int16": (">h", 2),
    "int16s": (">h", 2),
    "int32u": (">I", 4),
    "uint32": (">I", 4),
    "int32": (">i", 4),
    "int32s": (">i", 4),
    "int64": (">q", 8),
    "int64u": (">Q", 8),
    "uint64": (">Q", 8),
}

DECODE_OK = "ok"
DECODE_NOT_AVAILABLE = "not_available"
DECODE_INVALID = "invalid"


def is_even(number):
    return number % 2 == 0


def compute_modbus_crc16(data: bytes) -> int:
    """Compute standard Modbus RTU CRC-16 (polynomial 0xA001, little-endian on wire)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def append_modbus_crc16(pdu: bytes) -> bytes:
    """Append 2-byte little-endian Modbus CRC-16 to a raw RTU frame body."""
    crc = compute_modbus_crc16(pdu)
    return pdu + struct.pack("<H", crc)


def verify_modbus_crc16(frame: bytes) -> bool:
    """Verify the 2-byte CRC-16 at the end of a Modbus RTU frame."""
    if len(frame) < 4:
        return False
    expected = compute_modbus_crc16(frame[:-2])
    actual = struct.unpack("<H", frame[-2:])[0]
    return expected == actual


def describe_modbus_exception(code: int) -> str:
    name = MODBUS_EXCEPTION_NAMES.get(code, "unknown exception")
    return f"Modbus exception code 0x{code:02x} ({name})"


def _get_dbo_properties(mapping_dict, register_address):
    dbo_properties = mapping_dict[str(register_address)]
    total_registers = int(dbo_properties["number_of_registers"])
    total_bytes = total_registers * 2
    data_format = dbo_properties["format"]
    return total_registers, total_bytes, data_format


def flatten_meter_registers(data):
    """Flatten point register definitions and system register definitions into {reg_str: spec}."""
    flat = {}
    if not isinstance(data, dict):
        return flat
    for key, value in data.items():
        if key == "system" and isinstance(value, dict):
            for sys_reg, sys_spec in value.items():
                if isinstance(sys_spec, dict) and "number_of_registers" in sys_spec:
                    flat[str(sys_reg)] = sys_spec
        elif isinstance(value, dict) and "number_of_registers" in value:
            flat[str(key)] = value
    return flat


# Backward-compatible private alias.
_flatten_meter_registers = flatten_meter_registers


def get_register_offset(register_address, starting_address, total_bytes):
    """
    Calculate [start_byte, end_byte) inside RTU response data bytes for a 1-based register_address
    given a 0-based PDU starting_address.

    Example from PM5111:
        register_address = 3000 (1-based address in PM5111.json)
        starting_address = 2999 (0-based PDU address in incoming RTU request)
        start_index = ((3000 - 2999) * 2) - 2 = 0
        end_index = start_index + total_bytes
    """
    start_index = ((register_address - starting_address) * 2) - 2
    end_index = start_index + total_bytes
    return start_index, end_index


def _read_ext_config(directory, filename, config_file=None):
    """Read and cache external JSON configuration or meter register map."""
    if config_file is None:
        resources_path = os.path.join(ROOT_DIR, directory)
        if os.path.isdir(resources_path):
            config_file = os.path.join(resources_path, filename)
        else:
            config_file = os.path.join(ROOT_DIR, filename)

    abs_path = os.path.abspath(config_file)
    try:
        mtime = os.path.getmtime(abs_path)
        cached = _FILE_JSON_CACHE.get(abs_path)
        if cached is not None and cached[0] == mtime:
            return cached[1]
        with open(abs_path, "r", encoding="utf-8") as json_data_file:
            cfg_obj = json.load(json_data_file)
        _FILE_JSON_CACHE[abs_path] = (mtime, cfg_obj)
        return cfg_obj
    except (FileNotFoundError, IOError, OSError, ValueError) as e:
        logger.error(f"Invalid path or JSON in config file: {config_file}: {e}")
        return None


def map_modbus_slave_to_type(ext_conf):
    """
    Map integer modbus_slave_id -> meter type string (e.g. {1: 'PM5561', 2: 'PM5111'}).
    """
    if not isinstance(ext_conf, dict):
        return {}
    proxy_ids = ext_conf.get("site_details", {}).get("proxy_ids")
    if not isinstance(proxy_ids, dict):
        return {}
    transformed_dict = {}
    for _device, details in proxy_ids.items():
        if isinstance(details, dict) and "modbus_slave_id" in details and "type" in details:
            transformed_dict[int(details["modbus_slave_id"])] = details["type"]
    return transformed_dict


def decode_register_bytes(byte_value: bytes, data_format: str):
    """
    Decode raw big-endian (high word first) Modbus register bytes per the meter map format.

    Returns `(status, value)` where status is DECODE_OK, DECODE_NOT_AVAILABLE (the meter's
    "not available" sentinel, NaN/Inf or an empty string) or DECODE_INVALID.
    """
    fmt = str(data_format).lower()
    if fmt.startswith("str"):
        text = byte_value.decode("ascii", errors="ignore").replace("\x00", "").strip()
        if not text:
            return DECODE_NOT_AVAILABLE, None
        return DECODE_OK, text

    spec = _STRUCT_FORMATS.get(fmt)
    if spec is None:
        logger.warning(f"Unsupported Modbus register format: {data_format}")
        return DECODE_INVALID, None
    struct_fmt, size = spec
    if len(byte_value) != size:
        return DECODE_INVALID, None
    value = struct.unpack(struct_fmt, byte_value)[0]

    if fmt.startswith("float"):
        if math.isnan(value) or math.isinf(value):
            return DECODE_NOT_AVAILABLE, None
        return DECODE_OK, round(float(value), 6)
    if _INT_NOT_AVAILABLE.get(fmt) == value:
        return DECODE_NOT_AVAILABLE, None
    return DECODE_OK, value


def _decode_register_bytes(byte_value: bytes, data_format: str):
    """Backward-compatible helper returning only the decoded value (None if unusable)."""
    status, value = decode_register_bytes(byte_value, data_format)
    return value if status == DECODE_OK else None


def modbus_to_json(rtu_request, rtu_response, slave_to_type=None, dbo_maps=None, strict_crc=True):
    if not rtu_request or len(rtu_request) < 6:
        logger.debug("Ignoring Modbus RTU request shorter than 6 bytes")
        return None

    function_code = rtu_request[1]
    if function_code in (0x03, 0x04):
        return build_fc3_fc4_payload(
            rtu_request,
            rtu_response,
            slave_to_type=slave_to_type,
            dbo_maps=dbo_maps,
            strict_crc=strict_crc,
        )
    logger.debug(f"Modbus function code {function_code} is not decoded (only FC03/FC04)")
    return None


def _error_payload(payload, kind, message, exception_code=None):
    payload["error"] = message
    payload["error_kind"] = kind
    payload["exception_code"] = exception_code
    return json.dumps(payload)


def build_fc3_fc4_payload(
    rtu_request,
    rtu_response,
    slave_to_type=None,
    dbo_maps=None,
    strict_crc=True,
):
    """Build and return JSON payload string for Modbus FC03 (Holding) and FC04 (Input) registers."""
    slave_id, function_code, starting_address, quantity_of_registers = struct.unpack(
        ">BBHH", rtu_request[:6]
    )
    if function_code not in (0x03, 0x04):
        return None

    payload = {
        "slave_id": slave_id,
        "fc": function_code,
        "start_register": starting_address + 1,
        "quantity": quantity_of_registers,
        "data": None,
        "unavailable": {},
        "error": None,
        "error_kind": None,
        "exception_code": None,
    }

    if strict_crc and len(rtu_request) >= 8 and not verify_modbus_crc16(rtu_request[:8]):
        return _error_payload(payload, ERROR_CRC, "Modbus RTU request CRC-16 mismatch")

    if isinstance(rtu_response, Exception):
        return _error_payload(payload, ERROR_TRANSPORT, str(rtu_response))
    if rtu_response is None or len(rtu_response) < 5:
        return _error_payload(payload, ERROR_TRUNCATED, "Empty or truncated Modbus RTU response")

    if strict_crc and not verify_modbus_crc16(rtu_response):
        return _error_payload(payload, ERROR_CRC, "Modbus RTU response CRC-16 mismatch")

    resp_slave_id, resp_function_code, third_byte = struct.unpack(">BBB", rtu_response[:3])

    # Modbus exception response (function_code | 0x80)
    if resp_slave_id == slave_id and resp_function_code == (function_code | 0x80):
        return _error_payload(
            payload, ERROR_EXCEPTION, describe_modbus_exception(third_byte), third_byte
        )

    byte_count = third_byte
    if not all(
        (
            slave_id == resp_slave_id,
            function_code == resp_function_code,
            byte_count == quantity_of_registers * 2,
            len(rtu_response) == 3 + byte_count + 2,
        )
    ):
        return _error_payload(payload, ERROR_FRAMING, "Invalid Modbus RTU response framing")

    if slave_to_type is None:
        ext_conf = _read_ext_config("resources", "config-google-gateway.json")
        site_devices = map_modbus_slave_to_type(ext_conf)
    else:
        site_devices = {int(k): v for k, v in slave_to_type.items()}

    if resp_slave_id not in site_devices:
        logger.debug(f"Response slave ID {resp_slave_id} is not configured in site_details")
        return None

    meter_type = site_devices[resp_slave_id]
    if dbo_maps is not None and meter_type in dbo_maps:
        meter_map_raw = dbo_maps[meter_type]
    else:
        meter_map_raw = _read_ext_config("resources/modbus_dbo_maps", meter_type + ".json")

    if not meter_map_raw:
        logger.error(f"Meter map '{meter_type}' could not be loaded")
        return None

    flat_registers = flatten_meter_registers(meter_map_raw)
    rtu_response_bytes = rtu_response[3:-2]

    data_dict = {}
    for reg_str in flat_registers:
        try:
            reg_addr = int(reg_str)
        except ValueError:
            continue

        _total_registers, total_bytes, data_format = _get_dbo_properties(flat_registers, reg_addr)
        start_index, end_index = get_register_offset(reg_addr, starting_address, total_bytes)

        # Only decode registers completely contained in the received block
        if start_index < 0 or end_index > len(rtu_response_bytes):
            continue

        byte_value = rtu_response_bytes[start_index:end_index]
        status, decoded = decode_register_bytes(byte_value, data_format)
        if status == DECODE_OK:
            data_dict[reg_addr] = decoded
        elif status == DECODE_NOT_AVAILABLE:
            payload["unavailable"][str(reg_addr)] = f"N/A({byte_value.hex()})"

    payload["data"] = data_dict
    return json.dumps(payload)
