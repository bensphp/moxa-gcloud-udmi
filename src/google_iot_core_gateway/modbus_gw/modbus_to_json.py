# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

import json
import logging
import math
import os
import struct

from google_iot_core_gateway import ROOT_DIR

logger = logging.getLogger(__name__)

_FILE_JSON_CACHE = {}


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


def _get_dbo_properties(mapping_dict, register_address):
    dbo_properties = mapping_dict[str(register_address)]
    total_registers = int(dbo_properties["number_of_registers"])
    total_bytes = total_registers * 2
    data_format = dbo_properties["format"]
    return total_registers, total_bytes, data_format


def _flatten_meter_registers(data):
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
    logger.debug("START_BYTE_Index: {} END_BYTE_INDEX: {}".format(start_index, end_index))
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


def _decode_register_bytes(byte_value: bytes, data_format: str):
    """Decode raw big-endian Modbus register bytes according to meter map format."""
    fmt = data_format.lower()
    if fmt == "float32":
        if len(byte_value) != 4:
            return None
        val = struct.unpack(">f", byte_value)[0]
        if math.isnan(val) or math.isinf(val):
            return None
        return round(float(val), 6)
    if fmt == "float64":
        if len(byte_value) != 8:
            return None
        val = struct.unpack(">d", byte_value)[0]
        if math.isnan(val) or math.isinf(val):
            return None
        return round(float(val), 6)
    if fmt == "int64":
        return struct.unpack(">q", byte_value)[0] if len(byte_value) == 8 else None
    if fmt in ("int64u", "uint64"):
        return struct.unpack(">Q", byte_value)[0] if len(byte_value) == 8 else None
    if fmt in ("int32u", "uint32"):
        return struct.unpack(">I", byte_value)[0] if len(byte_value) == 4 else None
    if fmt in ("int32", "int32s"):
        return struct.unpack(">i", byte_value)[0] if len(byte_value) == 4 else None
    if fmt in ("int16u", "uint16"):
        return struct.unpack(">H", byte_value)[0] if len(byte_value) == 2 else None
    if fmt in ("int16", "int16s"):
        return struct.unpack(">h", byte_value)[0] if len(byte_value) == 2 else None
    if fmt.startswith("str"):
        text = byte_value.decode("ascii", errors="ignore").replace("\x00", "").strip()
        return text
    logger.warning(f"Unsupported Modbus register format: {data_format}")
    return None


def modbus_to_json(rtu_request, rtu_response, slave_to_type=None, dbo_maps=None, strict_crc=False):
    logger.debug("rtu_request: {}, rtu_response {}".format(rtu_request, rtu_response))
    if not rtu_request or len(rtu_request) < 6:
        logger.error("Invalid Modbus RTU request length")
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
    logger.error(f"Not implemented! Modbus to JSON parsing for function code: {function_code}")
    return None


def build_fc3_fc4_payload(
    rtu_request,
    rtu_response,
    slave_to_type=None,
    dbo_maps=None,
    strict_crc=False,
):
    """Build and return JSON payload string for Modbus FC03 (Holding) and FC04 (Input) registers."""
    slave_id, function_code, starting_address, quantity_of_registers = struct.unpack(
        ">BBHH", rtu_request[:6]
    )
    logger.debug(
        "req_slave_id: {} req_function_code:{} start_address:{} quantity:{}".format(
            slave_id, function_code, starting_address, quantity_of_registers
        )
    )

    if function_code not in (0x03, 0x04):
        return None

    payload = {
        "slave_id": slave_id,
        "fc": function_code,
        "data": None,
        "error": None,
    }

    if isinstance(rtu_response, Exception):
        payload["error"] = str(rtu_response)
        return json.dumps(payload)
    if rtu_response is None or len(rtu_response) < 5:
        payload["error"] = "Empty or truncated Modbus RTU response"
        return json.dumps(payload)

    # Validate CRC-16 when strict_crc is enabled or when non-zero CRC bytes are present
    if strict_crc or rtu_response[-2:] != b"\x00\x00":
        if not verify_modbus_crc16(rtu_response):
            payload["error"] = "Modbus RTU CRC-16 mismatch"
            logger.error(f"CRC mismatch on slave {slave_id} response")
            return json.dumps(payload)

    resp_slave_id, resp_function_code, third_byte = struct.unpack(">BBB", rtu_response[:3])

    # Check for Modbus exception response (function_code | 0x80)
    if resp_slave_id == slave_id and resp_function_code == (function_code | 0x80):
        payload["error"] = f"Modbus exception code 0x{third_byte:02x}"
        logger.warning(f"Slave {slave_id} returned {payload['error']}")
        return json.dumps(payload)

    byte_count = third_byte
    if not all(
        (
            slave_id == resp_slave_id,
            function_code == resp_function_code,
            byte_count == quantity_of_registers * 2,
            len(rtu_response) == 3 + byte_count + 2,
        )
    ):
        logger.error("Invalid Modbus RTU response framing")
        payload["error"] = "Invalid Modbus RTU response framing"
        return json.dumps(payload)

    if slave_to_type is None:
        ext_conf = _read_ext_config("resources", "config-google-gateway.json")
        site_devices = map_modbus_slave_to_type(ext_conf)
    else:
        site_devices = {int(k): v for k, v in slave_to_type.items()}

    if resp_slave_id not in site_devices:
        logger.error(
            f"[ERROR] Response Slave ID {resp_slave_id} not available in site_details"
        )
        return None

    meter_type = site_devices[resp_slave_id]
    if dbo_maps is not None and meter_type in dbo_maps:
        meter_map_raw = dbo_maps[meter_type]
    else:
        meter_map_raw = _read_ext_config("resources/modbus_dbo_maps", meter_type + ".json")

    if not meter_map_raw:
        logger.error(f"Meter map '{meter_type}' could not be loaded")
        return None

    flat_registers = _flatten_meter_registers(meter_map_raw)
    rtu_response_bytes = rtu_response[3:-2]

    data_dict = {}
    for reg_str, _spec in flat_registers.items():
        try:
            reg_addr = int(reg_str)
        except ValueError:
            continue

        total_registers, total_bytes, data_format = _get_dbo_properties(flat_registers, reg_addr)
        start_index, end_index = get_register_offset(reg_addr, starting_address, total_bytes)

        # Check complete containment within the received RTU register block
        if start_index < 0 or end_index > len(rtu_response_bytes):
            continue

        byte_value = rtu_response_bytes[start_index:end_index]
        decoded = _decode_register_bytes(byte_value, data_format)
        if decoded is not None:
            data_dict[reg_addr] = decoded

    payload["data"] = data_dict
    logger.debug(f"build_fc3_fc4_payload: {payload}")
    return json.dumps(payload)
