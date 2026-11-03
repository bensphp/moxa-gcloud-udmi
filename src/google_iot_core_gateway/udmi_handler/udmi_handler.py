import copy
import datetime
import json
import os
import re
import socket
import subprocess
import threading
import time

from google_iot_core_gateway import UDMI_VERSION, __version__ as GATEWAY_SOFTWARE_VERSION
from google_iot_core_gateway.udmi_handler.modbus_to_dbo import ModbusToDBO

# UDMI numerical log severity levels (Stackdriver LogSeverity)
LEVEL_DEBUG = 100
LEVEL_INFO = 200
LEVEL_NOTICE = 300
LEVEL_WARNING = 400
LEVEL_ERROR = 500

# Standard UDMI categories
CATEGORY_SYSTEM_BASE_READY = "system.base.ready"
CATEGORY_SYSTEM_CONFIG_RECEIVE = "system.config.receive"
CATEGORY_SYSTEM_CONFIG_PARSE = "system.config.parse"
CATEGORY_SYSTEM_CONFIG_APPLY = "system.config.apply"
CATEGORY_POINTSET_POINT_INVALID = "pointset.point.invalid"
CATEGORY_POINTSET_POINT_FAILURE = "pointset.point.failure"
CATEGORY_GATEWAY_PROXY_TARGET = "gateway.proxy.target"
CATEGORY_GATEWAY_PROXY_CONNECT = "gateway.proxy.connect"
CATEGORY_GATEWAY_SETUP_ATTACH = "gateway.setup.attach"

EPOCH_ISO = "1970-01-01T00:00:00Z"
STATE_THROTTLE_SEC = 2.1
INITIAL_CONFIG_WAIT_SEC = 10.0

UDMI_SUBBLOCKS = (
    "system",
    "gateway",
    "pointset",
    "localnet",
    "discovery",
    "blobset",
    "alarmset",
)

OFFICIAL_UDMI_BUCKETS = {
    "endpoint",
    "endpoint.config",
    "enumeration",
    "enumeration.pointset",
    "enumeration.features",
    "enumeration.families",
    "discovery",
    "discovery.scan",
    "gateway",
    "pointset",
    "system",
    "system.mode",
    "system.software",
    "system.software.updates",
    "writeback",
}

DEFAULT_GATEWAY_FEATURES = {
    "system": {"stage": "stable"},
    "pointset": {"stage": "stable"},
    "gateway": {"stage": "beta"},
    "system.mode": {"stage": "beta"},
    "enumeration": {"stage": "beta"},
    "enumeration.families": {"stage": "beta"},
    "enumeration.features": {"stage": "beta"},
    "enumeration.pointset": {"stage": "beta"},
}

DEFAULT_PROXY_FEATURES = {
    "system": {"stage": "stable"},
    "pointset": {"stage": "stable"},
    "gateway": {"stage": "beta"},
    "enumeration": {"stage": "beta"},
    "enumeration.families": {"stage": "beta"},
    "enumeration.features": {"stage": "beta"},
    "enumeration.pointset": {"stage": "beta"},
}


def _detect_host_network_families(preferred_config=None, metadata_localnet=None):
    """
    Discover local network addresses (ether, ipv4, ipv6) from the Linux host,
    reconciling multi-NIC gateways (e.g. Moxa UC8220 eth0/eth1) with configured
    or metadata expectations when present.
    """
    interfaces = []
    try:
        proc = subprocess.run(
            ["ip", "-j", "addr"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            for iface in json.loads(proc.stdout):
                if iface.get("ifname") == "lo":
                    continue
                entry = {"ifname": iface.get("ifname", "")}
                mac = iface.get("address")
                if mac and mac != "00:00:00:00:00:00":
                    entry["ether"] = mac.lower()
                for addr_info in iface.get("addr_info") or []:
                    fam = addr_info.get("family")
                    scope = addr_info.get("scope")
                    local = addr_info.get("local")
                    if not local or scope == "host":
                        continue
                    if fam == "inet" and "ipv4" not in entry:
                        entry["ipv4"] = local
                    elif fam == "inet6" and scope == "global" and "ipv6" not in entry:
                        entry["ipv6"] = local
                interfaces.append(entry)
    except Exception:
        pass

    # Fallback via /sys/class/net and socket if `ip -j addr` was unavailable
    if not interfaces and os.path.isdir("/sys/class/net"):
        for ifname in sorted(os.listdir("/sys/class/net")):
            if ifname == "lo":
                continue
            entry = {"ifname": ifname}
            addr_file = os.path.join("/sys/class/net", ifname, "address")
            try:
                with open(addr_file, "r", encoding="utf-8") as fh:
                    mac = fh.read().strip().lower()
                if mac and mac != "00:00:00:00:00:00":
                    entry["ether"] = mac
            except OSError:
                pass
            interfaces.append(entry)

    families = {}
    if interfaces:
        primary = interfaces[0]
        for key in ("ether", "ipv4", "ipv6"):
            for iface in interfaces:
                if key in iface:
                    families[key] = {"addr": iface[key]}
                    break
            if key in primary:
                families[key] = {"addr": primary[key]}

    if "ipv4" not in families:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                families["ipv4"] = {"addr": sock.getsockname()[0]}
        except OSError:
            pass

    # Reconcile multi-NIC selection or explicit metadata/config overrides
    meta_families = (metadata_localnet or {}).get("families") or {}
    for fam_name, fam_spec in meta_families.items():
        if not isinstance(fam_spec, dict):
            continue
        expected_addr = fam_spec.get("addr")
        if expected_addr:
            # Select matching NIC on multi-NIC gateways (eth0/eth1); only fall back to
            # metadata for non-OS fieldbus families (e.g. vendor/modbus) or if no NICs exist.
            matched_iface = next(
                (iface for iface in interfaces if iface.get(fam_name) == str(expected_addr).lower() or iface.get(fam_name) == str(expected_addr)),
                None,
            )
            if matched_iface is not None:
                families[fam_name] = {"addr": matched_iface[fam_name]}
            elif fam_name not in ("ether", "ipv4", "ipv6") or not families.get(fam_name):
                families[fam_name] = {"addr": str(expected_addr)}
        elif fam_name not in families:
            families[fam_name] = {}

    if isinstance(preferred_config, dict):
        pref_ifname = preferred_config.get("interface")
        if pref_ifname:
            for iface in interfaces:
                if iface.get("ifname") == pref_ifname:
                    for key in ("ether", "ipv4", "ipv6"):
                        if key in iface:
                            families[key] = {"addr": iface[key]}
                    break
        for fam_name, addr_val in (preferred_config.get("families") or {}).items():
            if isinstance(addr_val, dict):
                families[fam_name] = (
                    {"addr": str(addr_val["addr"])} if addr_val.get("addr") is not None else {}
                )
            elif isinstance(addr_val, str):
                families[fam_name] = {"addr": addr_val}

    return families


_MODBUS_UDMI_REF_RE = re.compile(
    r"^(?:modbus://[A-Za-z0-9_.:-]+/)?(?:(\d+)/)?(\d+)/(\d+)(?:/(\d+))?(?:\?(.*))?$"
)
_MODBUS_ALLOWED_FCS = {"1", "2", "3", "4", "5", "6", "15", "16"}
_MODBUS_ALLOWED_PARAMS = {"border", "type", "worder", "scale", "offset"}


def _build_proxied_localnet_families(metadata_localnet=None) -> dict:
    """Build `state.localnet.families` for a proxied device from its metadata only."""
    families = {}
    meta_families = (metadata_localnet or {}).get("families") or {}
    for fam_name, fam_spec in meta_families.items():
        if isinstance(fam_spec, dict) and fam_spec.get("addr") is not None:
            families[str(fam_name)] = {"addr": str(fam_spec["addr"])}
        else:
            families[str(fam_name)] = {}
    return families


def _detect_hardware_serial(default_serial: str) -> str:
    """Attempt to read hardware serial number on Linux/ARM gateways (e.g. Moxa UC8220)."""
    candidates = [
        "/sys/firmware/devicetree/base/serial-number",
        "/sys/class/dmi/id/product_serial",
    ]
    for path in candidates:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    serial = fh.read().replace("\x00", "").strip()
                if serial and serial not in ("0", "00000000", "None", "To be filled by O.E.M."):
                    return serial
        except OSError:
            continue
    return default_serial


def _collect_host_metrics() -> dict:
    """Collect lightweight host memory, storage, and load metrics using Python stdlib."""
    metrics = {}
    try:
        if os.path.exists("/proc/meminfo"):
            mem_kb = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.split(":")
                    if len(parts) == 2:
                        val_parts = parts[1].strip().split()
                        if val_parts:
                            mem_kb[parts[0].strip()] = int(val_parts[0])
            if "MemTotal" in mem_kb:
                metrics["mem_total_mb"] = round(mem_kb["MemTotal"] / 1024.0, 2)
            free_key = "MemAvailable" if "MemAvailable" in mem_kb else "MemFree"
            if free_key in mem_kb:
                metrics["mem_free_mb"] = round(mem_kb[free_key] / 1024.0, 2)
    except Exception:
        pass

    try:
        stat = os.statvfs("/")
        metrics["store_total_mb"] = round((stat.f_blocks * stat.f_frsize) / (1024.0 * 1024.0), 2)
        metrics["store_free_mb"] = round((stat.f_bavail * stat.f_frsize) / (1024.0 * 1024.0), 2)
    except Exception:
        pass

    try:
        metrics["system_load"] = round(os.getloadavg()[0], 2)
    except Exception:
        pass

    return metrics


class UDMIHandler:
    """
    UDMI 1.5.2+ compliant state, config, logging, localnet, gateway, and pointset manager
    for both the Moxa gateway device (e.g. CGW-2) and its proxied Modbus devices (e.g. EM-11..13).
    """

    def __init__(
        self,
        logger,
        resources_path,
        udmi_site_model_path,
        default_sample_rate_sec=30.0,
        config_wait_timeout_sec=INITIAL_CONFIG_WAIT_SEC,
    ):
        self.logger = logger
        self.resources_path = resources_path
        self.udmi_site_model_path = udmi_site_model_path
        self.default_sample_rate_sec = float(default_sample_rate_sec)
        self.config_wait_timeout_sec = float(config_wait_timeout_sec)

        self._lock = threading.RLock()
        self._last_ts_ms = 0
        self._boot_mono = time.monotonic()
        self._boot_iso = self._rounded_utc_now()

        # Backward-compatible slave_id (str) -> device record mapping for Modbus slaves
        self.devices = {}
        # All managed UDMI devices (gateway + proxied devices) keyed by device_id
        self.devices_by_id = {}
        self.gateway_id = None

        self._modbus_dbo_map = ModbusToDBO(logger, resources_path).map

    @staticmethod
    def _rounded_utc_now() -> str:
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        return now.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _next_start_iso_after(prev_iso: str) -> str:
        prev_sec = 0
        try:
            clean = str(prev_iso or "").strip()
            if clean.endswith("Z"):
                clean = clean[:-1] + "+00:00"
            prev_dt = datetime.datetime.fromisoformat(clean)
            prev_sec = int(prev_dt.timestamp())
        except Exception:
            prev_sec = 0
        next_sec = max(int(time.time()), prev_sec + 1)
        return datetime.datetime.fromtimestamp(next_sec, tz=datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    @staticmethod
    def _resolve_supported_features(metadata: dict, is_gateway: bool) -> dict:
        defaults = DEFAULT_GATEWAY_FEATURES if is_gateway else DEFAULT_PROXY_FEATURES
        meta_features = (metadata or {}).get("features")
        if isinstance(meta_features, dict) and meta_features:
            resolved = {}
            for key, spec in meta_features.items():
                if key not in OFFICIAL_UDMI_BUCKETS or not isinstance(spec, dict):
                    continue
                stage = str(spec.get("stage") or "stable")
                resolved[str(key)] = {"stage": stage}
            if resolved:
                return resolved
        return copy.deepcopy(defaults)

    def get_timestamp(self) -> str:
        """Return strictly monotonic RFC 3339 UTC timestamp with millisecond precision."""
        with self._lock:
            now_ms = int(time.time() * 1000)
            if now_ms <= self._last_ts_ms:
                now_ms = self._last_ts_ms + 1
            self._last_ts_ms = now_ms
        dt = datetime.datetime.fromtimestamp(now_ms / 1000.0, tz=datetime.timezone.utc)
        ms = now_ms % 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"

    def make_entry(self, category: str, level: int, message: str, detail: str = None, timestamp: str = None) -> dict:
        entry = {
            "category": category,
            "level": int(level),
            "message": str(message),
            "timestamp": timestamp or self.get_timestamp(),
        }
        if detail:
            entry["detail"] = str(detail)
        return entry

    def _load_device_metadata(self, device_id: str):
        metadata_file_path = os.path.join(
            self.udmi_site_model_path, "devices", device_id, "metadata.json"
        )
        if not os.path.exists(metadata_file_path):
            return None
        try:
            with open(metadata_file_path, "r", encoding="utf-8") as metadata_file:
                return json.load(metadata_file)
        except Exception as exc:
            self.logger.error(f"Failed to parse metadata for '{device_id}': {exc}")
            return None

    def _build_initial_subblocks(self, metadata: dict, is_gateway: bool) -> set:
        subblocks = {"system"}
        if isinstance(metadata, dict):
            for block in UDMI_SUBBLOCKS:
                if metadata.get(block) is not None:
                    subblocks.add(block)
        else:
            if is_gateway:
                subblocks.add("gateway")
            else:
                subblocks.update({"gateway", "pointset"})
        return subblocks

    def _create_base_device_record(
        self,
        device_id: str,
        is_gateway: bool,
        metadata: dict = None,
        serial_no: str = None,
        default_make: str = "Moxa",
        default_model: str = "UC8220",
        default_software: dict = None,
        localnet_config: dict = None,
    ) -> dict:
        sys_meta = (metadata or {}).get("system") or {}
        hw_meta = sys_meta.get("hardware") or {}
        sw_meta = sys_meta.get("software")

        hardware = {
            "make": str(hw_meta.get("make") or default_make),
            "model": str(hw_meta.get("model") or default_model),
        }
        if hw_meta.get("sku"):
            hardware["sku"] = str(hw_meta["sku"])
        if hw_meta.get("rev"):
            hardware["rev"] = str(hw_meta["rev"])

        if isinstance(sw_meta, dict) and sw_meta:
            software = {str(k): str(v) for k, v in sw_meta.items()}
            software_pinned = True
        else:
            software = dict(default_software or {"firmware": GATEWAY_SOFTWARE_VERSION})
            software_pinned = False

        hardware_pinned = bool(hw_meta.get("make") and hw_meta.get("model"))

        resolved_serial = (
            str(serial_no)
            if serial_no
            else str(sys_meta.get("serial_no") or "")
        )
        serial_pinned = bool(serial_no or sys_meta.get("serial_no"))
        if not resolved_serial:
            if is_gateway:
                resolved_serial = _detect_hardware_serial(f"{device_id}-SN")
            else:
                resolved_serial = f"{device_id}-SN"

        meta_points = copy.deepcopy(((metadata or {}).get("pointset") or {}).get("points") or {})
        active_subblocks = self._build_initial_subblocks(metadata, is_gateway=is_gateway)

        if is_gateway:
            localnet_families = _detect_host_network_families(
                preferred_config=localnet_config,
                metadata_localnet=(metadata or {}).get("localnet"),
            )
        else:
            localnet_families = _build_proxied_localnet_families(
                metadata_localnet=(metadata or {}).get("localnet"),
            )

        now_mono = time.monotonic()
        record = {
            "device_id": device_id,
            "is_gateway": is_gateway,
            "metadata": metadata or {},
            "hardware": hardware,
            "hardware_pinned": hardware_pinned,
            "software": software,
            "software_pinned": software_pinned,
            "serial_no": resolved_serial,
            "serial_pinned": serial_pinned,
            "last_config": EPOCH_ISO,
            "operational": True,
            "operation_mode": "active",
            "last_start": self._boot_iso,
            "restart_count": 1,
            "restart_handled": False,
            "system_status": None,
            "gateway_status": None,
            "min_loglevel": LEVEL_INFO,
            "metrics_rate_sec": 0.0,
            "next_metrics_mono": 0.0,
            "event_no": 0,
            "pending_logs": [],
            "discovery_generation": None,
            "pending_discovery_events": [],
            "supported_features": self._resolve_supported_features(metadata, is_gateway=is_gateway),
            "active_subblocks": active_subblocks,
            "localnet_families": localnet_families,
            "default_sample_rate_sec": self.default_sample_rate_sec,
            "sample_interval_sec": self.default_sample_rate_sec,
            "next_pointset_mono": now_mono + min(2.0, self.default_sample_rate_sec),
            "known_points": {},
            "enumerable_points": list(meta_points.keys())
            if isinstance(((metadata or {}).get("pointset") or {}).get("points"), dict)
            else None,
            "configured_points": {},
            "points": {},
            "has_received_config": False,
            "created_mono": now_mono,
            "state_dirty": True,
            "last_state_publish_mono": 0.0,
            "last_published_state_canonical": None,
        }

        # Populate initial known points & configured points from metadata
        for pt_name, pt_meta in meta_points.items():
            pt_meta = pt_meta or {}
            valid_refs = set()
            if pt_meta.get("ref") is not None:
                valid_refs.add(str(pt_meta["ref"]))
            record["known_points"][pt_name] = {
                "units": pt_meta.get("units"),
                "valid_refs": valid_refs,
            }
            record["configured_points"][pt_name] = dict(pt_meta)
            record["points"][pt_name] = {
                "present_value": None,
                "hardware_error": None,
            }

        # Queue initial system.base.ready notice log
        self._queue_log_locked(
            record,
            self.make_entry(
                CATEGORY_SYSTEM_BASE_READY,
                LEVEL_NOTICE,
                f"Device {device_id} initialized and ready",
            ),
        )
        return record

    def register_gateway(
        self,
        gateway_id: str,
        proxy_ids=None,
        serial_no: str = None,
        localnet_config: dict = None,
    ) -> bool:
        """Register the gateway device itself (e.g. CGW-2) as a first-class UDMI device."""
        with self._lock:
            metadata = self._load_device_metadata(gateway_id)
            if metadata is None:
                self.logger.warning(
                    f"Gateway '{gateway_id}' metadata.json not found in '{self.udmi_site_model_path}'; using defaults"
                )
            record = self._create_base_device_record(
                device_id=gateway_id,
                is_gateway=True,
                metadata=metadata,
                serial_no=serial_no,
                default_make="Moxa",
                default_model="UC8220",
                default_software={"firmware": GATEWAY_SOFTWARE_VERSION},
                localnet_config=localnet_config,
            )
            if proxy_ids is not None:
                record["configured_proxy_ids"] = list(proxy_ids)
            else:
                gw_meta_proxies = ((metadata or {}).get("gateway") or {}).get("proxy_ids") or []
                record["configured_proxy_ids"] = list(gw_meta_proxies)

            self.gateway_id = gateway_id
            self.devices_by_id[gateway_id] = record
            return True

    def add_device_to_dict(self, modbus_slave_id, device_id, device_type, serial_no=None):
        """
        Register a proxied Modbus slave device (e.g. EM-11 -> slave 1, PM5111).
        Maintains both `self.devices[str(modbus_slave_id)]` and `self.devices_by_id[device_id]`.
        """
        with self._lock:
            metadata = self._load_device_metadata(device_id)
            if metadata is None:
                self.logger.error(
                    f"Device '{device_id}' is not part of UDMI Site Model at '{self.udmi_site_model_path}'."
                )
                return False

            slave_key = str(modbus_slave_id)
            record = self._create_base_device_record(
                device_id=device_id,
                is_gateway=False,
                metadata=metadata,
                serial_no=serial_no,
                default_make="Schneider Electric",
                default_model=str(device_type),
                default_software={"firmware": "1.0"},
            )
            record["device_type"] = str(device_type)
            record["modbus_slave_id"] = slave_key

            # Configure valid gateway.target expectations for ProxiedSequences validation
            gw_meta = (metadata.get("gateway") or {})
            target_meta = gw_meta.get("target") or {}
            ln_families = ((metadata.get("localnet") or {}).get("families") or {})
            valid_families = {"modbus", "vendor"}
            if target_meta.get("family"):
                valid_families.add(str(target_meta["family"]))
            for fam_key in ln_families:
                valid_families.add(str(fam_key))
            valid_addrs = {
                slave_key,
                f"0x{int(modbus_slave_id):02x}",
                "ttyM0",
                "ttyM1",
                "ttyS0",
                "ttyUSB0",
            }
            if target_meta.get("addr") is not None:
                valid_addrs.add(str(target_meta["addr"]))
            for fam_spec in ln_families.values():
                if isinstance(fam_spec, dict) and fam_spec.get("addr") is not None:
                    valid_addrs.add(str(fam_spec["addr"]))
            record["valid_target_families"] = valid_families
            record["valid_target_addrs"] = valid_addrs

            # Enrich known_points and valid_refs from the meter's Modbus-to-DBO register map
            meter_map = self._modbus_dbo_map.get(str(device_type)) or {}
            for reg_str, spec in meter_map.items():
                if reg_str == "system" or not isinstance(spec, dict):
                    continue
                dbo_name = spec.get("dbo_name")
                if not dbo_name:
                    continue
                pt_info = record["known_points"].setdefault(
                    dbo_name, {"units": spec.get("units"), "valid_refs": set()}
                )
                pt_info["register"] = str(reg_str)
                pt_info["valid_refs"].update(
                    {
                        str(reg_str),
                        f"4{int(reg_str):04d}" if str(reg_str).isdigit() and int(reg_str) < 10000 else str(reg_str),
                        f"{reg_str}.{spec.get('format', '')}",
                    }
                )
                if dbo_name not in record["points"]:
                    record["points"][dbo_name] = {
                        "present_value": None,
                        "hardware_error": None,
                    }

            self.devices[slave_key] = record
            self.devices_by_id[device_id] = record
            return True

    def _resolve_device_locked(self, identifier) -> dict:
        key = str(identifier)
        if key in self.devices_by_id:
            return self.devices_by_id[key]
        if key in self.devices:
            return self.devices[key]
        return None

    def _queue_log_locked(self, dev: dict, entry: dict):
        if int(entry["level"]) >= int(dev["min_loglevel"]):
            dev["pending_logs"].append(entry)

    def _is_valid_point_ref(self, dev: dict, point_name: str, ref_value) -> bool:
        if ref_value is None:
            return True
        ref_str = str(ref_value).strip()
        if not ref_str:
            return True
        pt_info = dev["known_points"].get(point_name)
        if not pt_info:
            return False
        valid_refs = pt_info.get("valid_refs") or set()
        if ref_str in valid_refs:
            return True

        # Support UDMI 1.5 Modbus protocol refs:
        # [modbus://<addr>/][<unitid>/]<function>/<address>[/<quantity>][?<params>]
        match = _MODBUS_UDMI_REF_RE.match(ref_str)
        if match:
            unit_id, func_code, reg_addr, _qty, query = match.groups()
            expected_slave = str(dev.get("modbus_slave_id") or "")
            if unit_id is not None and expected_slave and unit_id != expected_slave:
                return False
            if func_code not in _MODBUS_ALLOWED_FCS:
                return False
            expected_reg = pt_info.get("register")
            if expected_reg is not None and reg_addr != str(expected_reg):
                return False
            if query:
                for param in query.split("&"):
                    if "=" not in param:
                        return False
                    key, val = param.split("=", 1)
                    if key not in _MODBUS_ALLOWED_PARAMS or not val:
                        return False
            return True

        if not valid_refs:
            return ref_str.isdigit()
        return False

    def set_modbus_poll_error(self, modbus_slave_id, error_message: str):
        """Record or clear a fieldbus communication error on a proxied Modbus device."""
        with self._lock:
            dev = self.devices.get(str(modbus_slave_id))
            if not dev:
                return
            if error_message:
                # Only update gateway_status if not already holding a config target error
                current_cat = (dev.get("gateway_status") or {}).get("category")
                if current_cat != CATEGORY_GATEWAY_PROXY_TARGET:
                    new_status = self.make_entry(
                        CATEGORY_GATEWAY_PROXY_CONNECT,
                        LEVEL_ERROR,
                        f"Modbus poll error: {error_message}",
                    )
                    if current_cat != CATEGORY_GATEWAY_PROXY_CONNECT:
                        dev["gateway_status"] = new_status
                        self._refresh_dirty_flag_locked(dev)
            else:
                current_cat = (dev.get("gateway_status") or {}).get("category")
                if current_cat == CATEGORY_GATEWAY_PROXY_CONNECT:
                    dev["gateway_status"] = None
                    self._refresh_dirty_flag_locked(dev)

    def update_device_properties(self, modbus_slave_id, device_type, registry_number, value):
        """
        Update a proxied device's point telemetry or system metadata from a decoded Modbus register.
        """
        if value is None or isinstance(value, bool):
            return
        if isinstance(value, str):
            # Reject legacy error/NaN strings for point values
            if value.startswith("[ERROR]") or value.startswith("N/A(") or value == "":
                return

        reg_key = str(registry_number)
        slave_key = str(modbus_slave_id)

        with self._lock:
            if device_type not in self._modbus_dbo_map:
                self.logger.error(
                    f"Modbus-to-DBO map is not defined for '{device_type}'."
                )
                return

            dev = self.devices.get(slave_key)
            if not dev:
                return

            # Clear any transient Modbus connect error upon valid data reception
            if (dev.get("gateway_status") or {}).get("category") == CATEGORY_GATEWAY_PROXY_CONNECT:
                dev["gateway_status"] = None

            meter_map = self._modbus_dbo_map[device_type]
            if reg_key in meter_map and reg_key != "system":
                self._update_device_points_present_value_locked(dev, meter_map, reg_key, value)
            elif "system" in meter_map and reg_key in meter_map["system"]:
                self._update_system_info_locked(dev, meter_map["system"], reg_key, value)

    def _update_system_info_locked(self, dev: dict, sys_map: dict, reg_key: str, value):
        point = sys_map[reg_key].get("dbo_name")
        str_val = str(value).strip()
        if not str_val:
            return

        changed = False
        if point == "serial_no" and not dev["serial_pinned"]:
            if dev["serial_no"] != str_val:
                dev["serial_no"] = str_val
                changed = True
        elif point in ("firmware_version", "version") and not dev["software_pinned"]:
            if dev["software"].get("firmware") != str_val:
                dev["software"]["firmware"] = str_val
                changed = True
        elif point == "manufacturer_name" and not dev["hardware_pinned"]:
            if dev["hardware"].get("make") != str_val:
                dev["hardware"]["make"] = str_val
                changed = True
        elif point in ("model_name", "product_name") and not dev["hardware_pinned"]:
            if point == "model_name" and dev["hardware"].get("model") != str_val:
                dev["hardware"]["model"] = str_val
                changed = True

        if changed:
            self._refresh_dirty_flag_locked(dev)

    def _update_device_points_present_value_locked(self, dev: dict, meter_map: dict, reg_key: str, value):
        if not isinstance(value, (int, float)):
            return
        point = meter_map[reg_key]["dbo_name"]
        pt_slot = dev["points"].setdefault(
            point, {"present_value": None, "hardware_error": None}
        )
        was_unread = pt_slot["present_value"] is None
        pt_slot["present_value"] = value
        pt_slot["hardware_error"] = None
        if was_unread and point in dev["configured_points"]:
            self._refresh_dirty_flag_locked(dev)

    def handle_config(self, device_id: str, raw_payload: str) -> bool:
        """
        Process a downlink UDMI `config` MQTT payload for either the gateway or a proxied device.
        Implements UDMI 1.5 config logging (`receive`, `parse`, `apply`), `broken_config` error
        state reporting without advancing `last_config`, `extra_config` tolerance, `min_loglevel`,
        subblock parity, dynamic `pointset`, and proxied `gateway.target` validation.
        """
        with self._lock:
            dev = self._resolve_device_locked(device_id)
            if dev is None:
                self.logger.warning(f"Ignoring config for unregistered device '{device_id}'")
                return False

            if raw_payload is None or len(raw_payload.strip()) == 0:
                self.logger.info(f"Received empty initial config for '{device_id}'; using defaults")
                dev["has_received_config"] = True
                self._refresh_dirty_flag_locked(dev)
                return True

            # Phase 1: RECEIVE (evaluated against current pre-apply min_loglevel)
            self._queue_log_locked(
                dev,
                self.make_entry(
                    CATEGORY_SYSTEM_CONFIG_RECEIVE,
                    LEVEL_DEBUG,
                    f"Received config for {device_id}",
                ),
            )

            # Phase 2: PARSE
            try:
                config = json.loads(raw_payload)
                if not isinstance(config, dict):
                    raise ValueError("Top-level config JSON must be an object")
            except Exception as exc:
                parse_err = self.make_entry(
                    CATEGORY_SYSTEM_CONFIG_PARSE,
                    LEVEL_ERROR,
                    f"Config JSON parse error: {exc}",
                    detail=repr(exc),
                )
                self._queue_log_locked(dev, parse_err)
                dev["system_status"] = {
                    "category": CATEGORY_SYSTEM_CONFIG_PARSE,
                    "level": LEVEL_ERROR,
                    "message": parse_err["message"],
                    "timestamp": parse_err["timestamp"],
                }
                dev["has_received_config"] = True
                self._refresh_dirty_flag_locked(dev, force_dirty=True)
                return False

            self._queue_log_locked(
                dev,
                self.make_entry(
                    CATEGORY_SYSTEM_CONFIG_PARSE,
                    LEVEL_DEBUG,
                    f"Parsed config for {device_id}",
                ),
            )

            # Phase 3: APPLY
            try:
                self._apply_parsed_config_locked(dev, config)
            except Exception as exc:
                apply_err = self.make_entry(
                    CATEGORY_SYSTEM_CONFIG_APPLY,
                    LEVEL_ERROR,
                    f"Config apply error: {exc}",
                    detail=repr(exc),
                )
                self._queue_log_locked(dev, apply_err)
                dev["system_status"] = {
                    "category": CATEGORY_SYSTEM_CONFIG_APPLY,
                    "level": LEVEL_ERROR,
                    "message": apply_err["message"],
                    "timestamp": apply_err["timestamp"],
                }
                dev["has_received_config"] = True
                self._refresh_dirty_flag_locked(dev, force_dirty=True)
                return False

            # Log apply success evaluated against newly applied min_loglevel
            self._queue_log_locked(
                dev,
                self.make_entry(
                    CATEGORY_SYSTEM_CONFIG_APPLY,
                    LEVEL_NOTICE,
                    f"Applied config {dev['last_config']} for {device_id}",
                ),
            )
            dev["has_received_config"] = True
            self._refresh_dirty_flag_locked(dev)
            return True

    def _apply_parsed_config_locked(self, dev: dict, config: dict):
        # 1. Exact subblock parity with incoming config (`system` is always required in state)
        new_subblocks = {"system"}
        for block in UDMI_SUBBLOCKS:
            if config.get(block) is not None:
                new_subblocks.add(block)
        dev["active_subblocks"] = new_subblocks

        # 2. System subblock
        sys_cfg = config.get("system")
        if isinstance(sys_cfg, dict):
            min_lvl = sys_cfg.get("min_loglevel")
            if isinstance(min_lvl, (int, float)) and not isinstance(min_lvl, bool):
                dev["min_loglevel"] = int(min_lvl)
            else:
                dev["min_loglevel"] = LEVEL_INFO

            metrics_rate = sys_cfg.get("metrics_rate_sec")
            if isinstance(metrics_rate, (int, float)) and metrics_rate > 0:
                dev["metrics_rate_sec"] = float(metrics_rate)
                if dev["next_metrics_mono"] <= 0:
                    dev["next_metrics_mono"] = time.monotonic() + dev["metrics_rate_sec"]
            else:
                dev["metrics_rate_sec"] = 0.0
                dev["next_metrics_mono"] = 0.0

            op_cfg = sys_cfg.get("operation")
            req_mode = op_cfg.get("mode") if isinstance(op_cfg, dict) else None
            if req_mode == "restart":
                if not dev["restart_handled"]:
                    dev["restart_handled"] = True
                    dev["restart_count"] += 1
                    dev["operation_mode"] = "initial"
                    dev["last_start"] = self._next_start_iso_after(dev["last_start"])
            else:
                dev["restart_handled"] = False
                if req_mode in ("active", None):
                    dev["operation_mode"] = "active"
                elif isinstance(req_mode, str) and req_mode:
                    dev["operation_mode"] = req_mode
        else:
            dev["min_loglevel"] = LEVEL_INFO
            dev["restart_handled"] = False
            dev["operation_mode"] = "active"

        # 3. Gateway subblock
        if "gateway" in new_subblocks:
            gw_cfg = config.get("gateway") or {}
            if dev["is_gateway"]:
                proxy_ids = gw_cfg.get("proxy_ids")
                if isinstance(proxy_ids, list):
                    dev["configured_proxy_ids"] = [str(p) for p in proxy_ids]
                dev["gateway_status"] = None
            else:
                target = gw_cfg.get("target")
                if isinstance(target, dict) and target:
                    fam = target.get("family")
                    addr = target.get("addr")
                    unit_id = target.get("unitid")
                    expected_slave = str(dev.get("modbus_slave_id") or "")
                    if fam is not None and str(fam) not in dev["valid_target_families"]:
                        dev["gateway_status"] = self.make_entry(
                            CATEGORY_GATEWAY_PROXY_TARGET,
                            LEVEL_ERROR,
                            f"Unsupported gateway target family '{fam}'",
                        )
                    elif addr is not None and str(addr) not in dev["valid_target_addrs"]:
                        dev["gateway_status"] = self.make_entry(
                            CATEGORY_GATEWAY_PROXY_TARGET,
                            LEVEL_ERROR,
                            f"Invalid gateway target address '{addr}'",
                        )
                    elif unit_id is not None and expected_slave and str(unit_id) != expected_slave:
                        dev["gateway_status"] = self.make_entry(
                            CATEGORY_GATEWAY_PROXY_TARGET,
                            LEVEL_ERROR,
                            f"Invalid gateway target unitid '{unit_id}'",
                        )
                    else:
                        dev["gateway_status"] = None
                else:
                    dev["gateway_status"] = None
        else:
            dev["gateway_status"] = None

        # 4. Localnet subblock
        if "localnet" in new_subblocks:
            ln_cfg = config.get("localnet") or {}
            cfg_families = ln_cfg.get("families")
            if isinstance(cfg_families, dict):
                for fam_name in cfg_families:
                    dev["localnet_families"].setdefault(fam_name, {})

        # 5. Pointset subblock
        if "pointset" in new_subblocks:
            ps_cfg = config.get("pointset") or {}
            new_interval = self._compute_sample_interval(
                ps_cfg.get("sample_rate_sec"),
                ps_cfg.get("sample_limit_sec"),
                dev["default_sample_rate_sec"],
            )
            now_mono = time.monotonic()
            if abs(new_interval - dev["sample_interval_sec"]) > 1e-6:
                dev["sample_interval_sec"] = new_interval
                dev["next_pointset_mono"] = now_mono + min(1.0, new_interval)
            elif dev["next_pointset_mono"] > now_mono + new_interval:
                dev["next_pointset_mono"] = now_mono + min(1.0, new_interval)

            if "points" in ps_cfg and isinstance(ps_cfg["points"], dict):
                new_cfg_points = {}
                for pt_name, pt_spec in ps_cfg["points"].items():
                    new_cfg_points[str(pt_name)] = dict(pt_spec) if isinstance(pt_spec, dict) else {}
            else:
                new_cfg_points = {}

            points_changed = new_cfg_points != dev["configured_points"]
            dev["configured_points"] = new_cfg_points
            if points_changed:
                dev["next_pointset_mono"] = min(
                    dev["next_pointset_mono"], now_mono + min(1.5, new_interval)
                )

        # 6. Discovery subblock (self-enumeration)
        if "discovery" in new_subblocks:
            disc_cfg = config.get("discovery") or {}
            gen = disc_cfg.get("generation") if isinstance(disc_cfg, dict) else None
            if gen is not None:
                gen_str = str(gen)
                if gen_str != dev["discovery_generation"]:
                    dev["discovery_generation"] = gen_str
                    enumerations = disc_cfg.get("enumerations")
                    if not isinstance(enumerations, dict):
                        enumerations = {}
                    disc_event = self._build_self_enumeration_event_locked(
                        dev, gen_str, enumerations
                    )
                    dev["pending_discovery_events"].append(disc_event)
            else:
                dev["discovery_generation"] = None
        else:
            dev["discovery_generation"] = None

        # 7. Update last_config and clear system_status on clean apply
        if config.get("timestamp"):
            dev["last_config"] = str(config["timestamp"])
        dev["system_status"] = None

    @staticmethod
    def _compute_sample_interval(sample_rate_sec, sample_limit_sec, default_sec: float) -> float:
        rate = (
            float(sample_rate_sec)
            if isinstance(sample_rate_sec, (int, float))
            and not isinstance(sample_rate_sec, bool)
            and sample_rate_sec > 0
            else None
        )
        limit = (
            float(sample_limit_sec)
            if isinstance(sample_limit_sec, (int, float))
            and not isinstance(sample_limit_sec, bool)
            and sample_limit_sec > 0
            else None
        )
        if rate is not None and limit is not None:
            if limit < rate:
                return (limit + rate) / 2.0
            return max(limit, rate)
        if rate is not None:
            return rate
        if limit is not None:
            return max(limit, default_sec)
        return default_sec

    def _build_point_state_entry_locked(self, dev: dict, pt_name: str, pt_cfg: dict) -> dict:
        if pt_name not in dev["known_points"]:
            return {
                "value_state": "invalid",
                "status": self.make_entry(
                    CATEGORY_POINTSET_POINT_INVALID,
                    LEVEL_ERROR,
                    f"Unknown configured point {pt_name}",
                ),
            }

        ref_val = (pt_cfg or {}).get("ref")
        if ref_val is not None and not self._is_valid_point_ref(dev, pt_name, ref_val):
            return {
                "value_state": "failure",
                "status": self.make_entry(
                    CATEGORY_POINTSET_POINT_FAILURE,
                    LEVEL_ERROR,
                    f"Invalid point ref '{ref_val}' for point {pt_name}",
                ),
            }

        pt_slot = dev["points"].get(pt_name) or {}
        if pt_slot.get("hardware_error"):
            return {
                "value_state": "failure",
                "status": self.make_entry(
                    CATEGORY_POINTSET_POINT_FAILURE,
                    LEVEL_ERROR,
                    str(pt_slot["hardware_error"]),
                ),
            }

        if not dev["is_gateway"] and pt_slot.get("present_value") is None:
            return {
                "value_state": "failure",
                "status": self.make_entry(
                    CATEGORY_POINTSET_POINT_FAILURE,
                    LEVEL_ERROR,
                    f"No Modbus reading received for point {pt_name}",
                ),
            }

        return {}

    def _build_state_body_locked(self, dev: dict) -> dict:
        """Build UDMI 1.5 state dict without top-level timestamp (used for diffing & serialization)."""
        system_block = {
            "hardware": copy.deepcopy(dev["hardware"]),
            "software": copy.deepcopy(dev["software"]),
            "serial_no": str(dev["serial_no"]),
            "last_config": str(dev["last_config"]),
            "operation": {
                "operational": bool(dev["operational"]),
                "last_start": str(dev["last_start"]),
                "restart_count": int(dev["restart_count"]),
                "mode": str(dev["operation_mode"]),
            },
        }
        if dev.get("system_status") is not None:
            system_block["status"] = copy.deepcopy(dev["system_status"])

        state = {
            "version": UDMI_VERSION,
            "system": system_block,
        }

        subblocks = dev["active_subblocks"]
        if "gateway" in subblocks:
            gw_block = {}
            if dev.get("gateway_status") is not None:
                gw_block["status"] = copy.deepcopy(dev["gateway_status"])
            state["gateway"] = gw_block

        if "localnet" in subblocks:
            state["localnet"] = {
                "families": copy.deepcopy(dev["localnet_families"]),
            }

        if "pointset" in subblocks:
            points_state = {}
            for pt_name, pt_cfg in dev["configured_points"].items():
                points_state[pt_name] = self._build_point_state_entry_locked(dev, pt_name, pt_cfg)
            state["pointset"] = {"points": points_state}

        if "discovery" in subblocks:
            disc_block = {"families": {}}
            if dev.get("discovery_generation") is not None:
                disc_block["generation"] = str(dev["discovery_generation"])
            state["discovery"] = disc_block
        if "blobset" in subblocks:
            state["blobset"] = {"blobs": {}}
        if "alarmset" in subblocks:
            state["alarmset"] = {"alarms": {}}

        return state

    def _build_self_enumeration_event_locked(
        self, dev: dict, generation: str, enumerations: dict
    ) -> dict:
        """Build a UDMI 1.5 `events/discovery` self-enumeration payload."""
        event = {
            "version": UDMI_VERSION,
            "timestamp": self.get_timestamp(),
            "generation": str(generation),
        }

        fam_depth = enumerations.get("families")
        if fam_depth in ("entries", "details"):
            use_details = fam_depth == "details"
            families_out = {}
            for fam_name, fam_info in dev["localnet_families"].items():
                if use_details and isinstance(fam_info, dict) and fam_info.get("addr"):
                    families_out[fam_name] = {"addr": str(fam_info["addr"])}
                else:
                    families_out[fam_name] = {}
            event["families"] = families_out

        feat_depth = enumerations.get("features")
        if feat_depth in ("entries", "details"):
            event["features"] = copy.deepcopy(dev["supported_features"])

        pts_depth = enumerations.get("points")
        if pts_depth in ("entries", "details"):
            use_details = pts_depth == "details"
            point_names = (
                dev["enumerable_points"]
                if dev.get("enumerable_points") is not None
                else list(dev["known_points"].keys())
            )
            points_out = {}
            for pt_name in point_names:
                pt_info = dev["known_points"].get(pt_name) or {}
                pt_entry = {}
                if use_details and isinstance(pt_info, dict):
                    if pt_info.get("units"):
                        pt_entry["units"] = str(pt_info["units"])
                    if pt_info.get("register"):
                        pt_entry["ref"] = str(pt_info["register"])
                points_out[pt_name] = pt_entry
            event["points"] = points_out

        return event

    def pop_due_discovery_events(self, device_id: str) -> list:
        """Pop all queued `events/discovery` JSON strings for `device_id`."""
        with self._lock:
            dev = self._resolve_device_locked(device_id)
            if dev is None or not dev["pending_discovery_events"]:
                return []
            events = [json.dumps(ev) for ev in dev["pending_discovery_events"]]
            dev["pending_discovery_events"].clear()
            return events

    @staticmethod
    def _canonicalize_state_for_diff(state_body: dict) -> str:
        """Canonicalize state while ignoring inner status entry timestamps so identical errors don't spam state."""
        normalized = copy.deepcopy(state_body)

        def _strip_entry_ts(obj):
            if isinstance(obj, dict):
                if "category" in obj and "level" in obj and "timestamp" in obj:
                    obj.pop("timestamp", None)
                for val in obj.values():
                    _strip_entry_ts(val)
            elif isinstance(obj, list):
                for item in obj:
                    _strip_entry_ts(item)

        _strip_entry_ts(normalized)
        return json.dumps(normalized, sort_keys=True)

    def _refresh_dirty_flag_locked(self, dev: dict, force_dirty: bool = False):
        if force_dirty:
            dev["state_dirty"] = True
            return
        body = self._build_state_body_locked(dev)
        canonical = self._canonicalize_state_for_diff(body)
        if canonical != dev["last_published_state_canonical"]:
            dev["state_dirty"] = True

    def get_state_payload(self, identifier) -> str:
        """
        Unconditionally build and serialize a UDMI 1.5 `state` JSON payload for `identifier`
        (accepts either `device_id` or `modbus_slave_id` for backward compatibility).
        """
        with self._lock:
            dev = self._resolve_device_locked(identifier)
            if dev is None:
                raise KeyError(f"Unknown device '{identifier}'")
            state_body = self._build_state_body_locked(dev)
            canonical = self._canonicalize_state_for_diff(state_body)
            state_body["timestamp"] = self.get_timestamp()
            dev["last_published_state_canonical"] = canonical
            dev["last_state_publish_mono"] = time.monotonic()
            dev["state_dirty"] = False
            return json.dumps(state_body)

    def pop_due_state_payload(self, device_id: str, now_mono: float = None):
        """
        Return serialized `state` JSON if `device_id` has dirty state, has received its initial
        config (or passed the startup wait timeout), and satisfies the 2s state throttle.
        """
        with self._lock:
            dev = self._resolve_device_locked(device_id)
            if dev is None or not dev["state_dirty"]:
                return None
            if now_mono is None:
                now_mono = time.monotonic()

            if not dev["has_received_config"]:
                if (now_mono - dev["created_mono"]) < self.config_wait_timeout_sec:
                    return None

            if dev["last_state_publish_mono"] > 0 and (
                now_mono - dev["last_state_publish_mono"]
            ) < STATE_THROTTLE_SEC:
                return None

            return self.get_state_payload(dev["device_id"])

    def pop_due_system_event_payload(self, device_id: str, now_mono: float = None):
        """
        Return serialized `events/system` JSON if `device_id` has queued log entries
        or if periodic host metrics are due.
        """
        with self._lock:
            dev = self._resolve_device_locked(device_id)
            if dev is None:
                return None
            if now_mono is None:
                now_mono = time.monotonic()

            metrics_due = (
                dev["is_gateway"]
                and dev["metrics_rate_sec"] > 0
                and now_mono >= dev["next_metrics_mono"]
            )
            has_logs = len(dev["pending_logs"]) > 0

            if not has_logs and not metrics_due:
                return None

            flushed_logs = list(dev["pending_logs"])
            dev["pending_logs"].clear()
            dev["event_no"] += 1

            payload = {
                "version": UDMI_VERSION,
                "timestamp": self.get_timestamp(),
                "event_no": dev["event_no"],
                "last_config": dev["last_config"],
            }
            if flushed_logs:
                payload["logentries"] = flushed_logs
            if metrics_due:
                payload["metrics"] = _collect_host_metrics()
                dev["next_metrics_mono"] = now_mono + dev["metrics_rate_sec"]

            return json.dumps(payload)

    def get_event_point_payload(self, identifier) -> str:
        """
        Build and serialize a UDMI 1.5 `events/pointset` JSON payload for `identifier`
        (accepts either `device_id` or `modbus_slave_id`).
        Only includes configured valid points with numeric values (empty `{}` on gateways
        with empty `pointset.points`).
        """
        with self._lock:
            dev = self._resolve_device_locked(identifier)
            if dev is None:
                raise KeyError(f"Unknown device '{identifier}'")

            points_out = {}
            for pt_name, pt_cfg in dev["configured_points"].items():
                if pt_name not in dev["known_points"]:
                    continue
                ref_val = (pt_cfg or {}).get("ref")
                if ref_val is not None and not self._is_valid_point_ref(dev, pt_name, ref_val):
                    continue
                pt_slot = dev["points"].get(pt_name) or {}
                if pt_slot.get("hardware_error"):
                    continue
                val = pt_slot.get("present_value")
                if isinstance(val, (int, float)) and not isinstance(val, bool):
                    points_out[pt_name] = {"present_value": val}

            data = {
                "version": UDMI_VERSION,
                "timestamp": self.get_timestamp(),
                "points": points_out,
            }
            return json.dumps(data)

    def pop_due_pointset_event_payload(self, device_id: str, now_mono: float = None):
        """
        Return serialized `events/pointset` JSON if `pointset` is active for `device_id`
        and its per-device `sample_interval_sec` timer has elapsed.
        """
        with self._lock:
            dev = self._resolve_device_locked(device_id)
            if dev is None:
                return None
            if "pointset" not in dev["active_subblocks"]:
                return None
            if now_mono is None:
                now_mono = time.monotonic()

            if not dev["has_received_config"]:
                if (now_mono - dev["created_mono"]) < self.config_wait_timeout_sec:
                    return None

            if now_mono < dev["next_pointset_mono"]:
                return None

            dev["next_pointset_mono"] = now_mono + dev["sample_interval_sec"]
            return self.get_event_point_payload(dev["device_id"])

    def get_active_device_ids(self) -> list:
        """Return ordered list of active UDMI device IDs (gateway first, then configured proxies)."""
        with self._lock:
            ordered = []
            allowed_proxies = None
            if self.gateway_id and self.gateway_id in self.devices_by_id:
                ordered.append(self.gateway_id)
                gw_dev = self.devices_by_id[self.gateway_id]
                if "configured_proxy_ids" in gw_dev:
                    allowed_proxies = set(gw_dev["configured_proxy_ids"])

            for dev_id, dev in self.devices_by_id.items():
                if dev["is_gateway"]:
                    continue
                if allowed_proxies is not None and dev_id not in allowed_proxies:
                    continue
                ordered.append(dev_id)
            return ordered
