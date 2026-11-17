#!/usr/bin/env python3
# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

import json
import math
import os

from google_iot_core_gateway import ROOT_DIR
from google_iot_core_gateway.errors import GatewayConfigError
from google_iot_core_gateway.modbus_gw.modbus_rtu_poller import (
    MODBUS_TRANSPORTS,
    VALID_BAUDRATES,
    VALID_BYTESIZES,
    VALID_PARITIES,
    VALID_STOPBITS,
)
from google_iot_core_gateway.modbus_gw.modbus_tcp_poller import POLL_MODES
from google_iot_core_gateway.utils.log import update_logger_verbose_level
from google_iot_core_gateway.utils.pointset_buffer import DEFAULT_OFFLINE_BUFFER_MAX

SECRET_SUBSTRINGS = ("password", "secret", "token", "passphrase")
SYSTEM_STATE_DIR = "/var/lib/moxa-gcloud-udmi"
CRC_CHECK_MODES = ("strict", "off")


def _is_secret_key(key) -> bool:
    lowered = str(key).lower()
    return any(part in lowered for part in SECRET_SUBSTRINGS)


def redact_secrets(obj):
    """Return a copy of a parsed config with secret values replaced, for logging."""
    if isinstance(obj, dict):
        return {
            key: ("***" if _is_secret_key(key) and value else redact_secrets(value))
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [redact_secrets(item) for item in obj]
    return obj


def _is_writable_dir(path: str) -> bool:
    if os.path.isdir(path):
        return os.access(path, os.W_OK)
    parent = os.path.dirname(path.rstrip("/")) or "/"
    return os.path.isdir(parent) and os.access(parent, os.W_OK)


def default_state_dir() -> str:
    """systemd StateDirectory= > /var/lib/moxa-gcloud-udmi (if writable) > ~/.local/state/..."""
    env_dir = os.environ.get("STATE_DIRECTORY")
    if env_dir:
        return env_dir.split(":")[0]
    if _is_writable_dir(SYSTEM_STATE_DIR):
        return SYSTEM_STATE_DIR
    return os.path.join(os.path.expanduser("~"), ".local", "state", "moxa-gcloud-udmi")


def _arg_value(args, name: str):
    if args is None:
        return None
    if isinstance(args, dict):
        return args.get(name)
    try:
        obj_vars = vars(args)
        if name in obj_vars:
            return obj_vars[name]
    except TypeError:
        pass
    for cls in type(args).__mro__:
        cls_vars = vars(cls)
        if name in cls_vars:
            return cls_vars[name]
    return None


def _require_bool(value, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise GatewayConfigError(f"{field_name} must be a boolean, got {type(value).__name__}")
    return value


def _require_int(value, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GatewayConfigError(f"{field_name} must be an integer, got {type(value).__name__}")
    return value


def _require_finite_number(value, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise GatewayConfigError(f"{field_name} must be a finite number, got {value!r}")
    return float(value)


def _require_non_empty_str(value, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GatewayConfigError(f"{field_name} must be a non-empty string")
    return value.strip()


def _require_section_dict(ext_conf: dict, section_name: str) -> dict:
    raw = ext_conf.get(section_name)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise GatewayConfigError(f"{section_name} must be an object")
    return raw


class ConfigHandler:

    def __init__(self, logger, args=None, root_dir=None):
        self.logger = logger

        if root_dir is None:
            root_dir = str(ROOT_DIR)
        else:
            root_dir = str(root_dir)

        # Default configuration will be loaded if not specified in config file
        self.internal_broker__enabled = True
        self.internal_broker__mqtt_bridge_hostname = "127.0.0.1"
        self.internal_broker__mqtt_bridge_port = 1883
        self.internal_broker__topic = "MXcloudgate"
        self.internal_broker__trusted_root_ca = None
        self.internal_broker__x509_certificate = None
        self.internal_broker__private_key = None
        self.internal_broker__tls_insecure_set = False
        self.internal_broker__enable_tls = False

        self.google_cloud__iot_provider = "iot_core"
        self.google_cloud__cloud_region = "us-central1"
        self.google_cloud__project_id = "your-project-id"
        self.google_cloud__sample_rate_set = 300  # UDMI config_pointset.json default
        self.google_cloud__mqtt_bridge_hostname = "mqtt.googleapis.com"
        self.google_cloud__mqtt_bridge_port = 8883
        self.google_cloud__enable_tls = True
        self.google_cloud__ca_cert = None
        self.google_cloud__client_cert = None
        self.google_cloud__client_key = None
        self.google_cloud__mqtt_username = None
        self.google_cloud__mqtt_password = None
        self.google_cloud__jwt_expires_minutes = 60
        self.google_cloud__offline_buffer_max_messages = DEFAULT_OFFLINE_BUFFER_MAX

        self.modbus__stale_timeout_sec = 300.0
        self.modbus__crc_check = "strict"
        self.modbus__poll_mode = "off"
        self.modbus__transport = "tcp"
        self.modbus__poll_host = "127.0.0.1"
        self.modbus__poll_port = 502
        self.modbus__poll_interval_sec = 10.0
        self.modbus__poll_timeout_sec = 2.0
        self.modbus__serial_port = None
        self.modbus__serial_ports = {}
        self.modbus__baudrate = 9600
        self.modbus__bytesize = 8
        self.modbus__parity = "N"
        self.modbus__stopbits = 1
        self.modbus__rs485_mode = False

        # Placeholders (the UDMI reference site name); the site model's cloud_iot_config.json sets them.
        self.site_details__name = "ZZ-TRI-FECTA"
        self.site_details__registry_id = "ZZ-TRI-FECTA"
        self.site_details__gateway_id = "CGW-1"
        self.site_details__serial_no = None
        self.site_details__localnet = None
        self.site_details__hardware = None
        self.site_details__gateway_points_enabled = False
        self.site_details__devices = {
            "EM-1": {
                "id": "",
                "type": "simulator",
                "modbus_slave_id": 1,
            }
        }
        self._explicit_cloud_region = False
        self._explicit_registry_id = False

        self.udmi_site_model_path = "/home/moxa/udmi_site_model"
        self.state_dir = None
        self.resources_path = os.path.join(root_dir, "resources")
        if not os.path.isdir(self.resources_path):
            self.resources_path = root_dir

        arg_resources_path = _arg_value(args, "resources_path")
        if arg_resources_path is not None:
            self.resources_path = arg_resources_path

        self._google_cloud_config_file = os.path.join(
            self.resources_path, "config-google-gateway.json"
        )
        if args:
            verbose_level = _arg_value(args, "verbose_level")
            if verbose_level is not None:
                update_logger_verbose_level(logger, verbose_level)
            google_cloud_cfg = _arg_value(args, "google_cloud_config_file")
            config_file = _arg_value(args, "config_file")
            if google_cloud_cfg is not None:
                self._google_cloud_config_file = google_cloud_cfg
            elif config_file is not None:
                self._google_cloud_config_file = config_file

        self._parse_module_configuration()
        self._parse_args_configuration(args)
        self._parse_udmi_site_model_configuration()
        # Re-apply explicit CLI overrides on top of cloud_iot_config.json
        self._parse_site_cli_overrides(args)
        if not self.state_dir:
            self.state_dir = default_state_dir()
        self._validate()
        self._print_configuration()

    def _read_ext_config(self, config_file=None):
        """Read JSON configuration file."""
        if config_file is None:
            config_file = self._google_cloud_config_file
        self.logger.info(f"Reading configuration: {config_file}")
        try:
            with open(config_file, "r", encoding="utf-8") as json_data_file:
                cfg_obj = json.load(json_data_file)
        except (OSError, ValueError) as e:
            raise GatewayConfigError(f"Cannot read configuration file '{config_file}': {e}") from e
        if not isinstance(cfg_obj, dict):
            raise GatewayConfigError(f"Configuration file '{config_file}' must be a JSON object")
        self.logger.debug(f"Configuration content: {redact_secrets(cfg_obj)}")
        return cfg_obj

    def _parse_udmi_site_model_configuration(self):
        """Read UDMI Site Model cloud_iot_config.json for registry/region details."""
        udmi_site_model_config = os.path.join(
            self.udmi_site_model_path, "cloud_iot_config.json"
        )
        if not os.path.exists(udmi_site_model_config) and self._explicit_cloud_region and self._explicit_registry_id:
            self.logger.warning(
                f"UDMI site model '{udmi_site_model_config}' not found; using explicit "
                "cloud_region and registry_id"
            )
            return
        ext_conf = self._read_ext_config(config_file=udmi_site_model_config)
        if not ext_conf:
            raise GatewayConfigError(f"Empty UDMI site model configuration '{udmi_site_model_config}'")

        if ext_conf.get("cloud_region"):
            self.google_cloud__cloud_region = ext_conf["cloud_region"]
        if ext_conf.get("site_name"):
            self.site_details__name = ext_conf["site_name"]
        if ext_conf.get("registry_id"):
            self.site_details__registry_id = ext_conf["registry_id"]

    def _parse_module_configuration(self):
        """Read config-google-gateway.json for Internal Broker, Cloud, and Modbus proxy devices."""
        ext_conf = self._read_ext_config()
        if not ext_conf:
            raise GatewayConfigError(f"Empty module configuration '{self._google_cloud_config_file}'")

        internal = _require_section_dict(ext_conf, "internal_broker")
        if "enabled" in internal:
            self.internal_broker__enabled = _require_bool(
                internal["enabled"], "internal_broker.enabled"
            )
        if internal.get("mqtt_bridge_hostname"):
            self.internal_broker__mqtt_bridge_hostname = internal["mqtt_bridge_hostname"]
        if internal.get("mqtt_bridge_port") is not None:
            self.internal_broker__mqtt_bridge_port = _require_int(
                internal["mqtt_bridge_port"], "internal_broker.mqtt_bridge_port"
            )
        if internal.get("topic"):
            self.internal_broker__topic = str(internal["topic"])
        if internal.get("trusted_root_ca"):
            self.internal_broker__trusted_root_ca = internal["trusted_root_ca"]
        if internal.get("x509_certificate"):
            self.internal_broker__x509_certificate = internal["x509_certificate"]
        if internal.get("private_key"):
            self.internal_broker__private_key = internal["private_key"]
        if "tls_insecure_set" in internal and internal["tls_insecure_set"] is not None:
            self.internal_broker__tls_insecure_set = _require_bool(
                internal["tls_insecure_set"], "internal_broker.tls_insecure_set"
            )
        if "enable_tls" in internal and internal["enable_tls"] is not None:
            self.internal_broker__enable_tls = _require_bool(
                internal["enable_tls"], "internal_broker.enable_tls"
            )

        gcloud = _require_section_dict(ext_conf, "google_cloud")
        if gcloud.get("iot_provider"):
            self.google_cloud__iot_provider = gcloud["iot_provider"]
        if gcloud.get("cloud_region"):
            self.google_cloud__cloud_region = gcloud["cloud_region"]
            self._explicit_cloud_region = True
        if gcloud.get("project_id"):
            self.google_cloud__project_id = gcloud["project_id"]
        if gcloud.get("sample_rate_set") is not None:
            self.google_cloud__sample_rate_set = _require_finite_number(
                gcloud["sample_rate_set"], "google_cloud.sample_rate_set"
            )
        if gcloud.get("mqtt_bridge_hostname"):
            self.google_cloud__mqtt_bridge_hostname = gcloud["mqtt_bridge_hostname"]
        if gcloud.get("mqtt_bridge_port") is not None:
            self.google_cloud__mqtt_bridge_port = _require_int(
                gcloud["mqtt_bridge_port"], "google_cloud.mqtt_bridge_port"
            )
        if "enable_tls" in gcloud and gcloud["enable_tls"] is not None:
            self.google_cloud__enable_tls = _require_bool(
                gcloud["enable_tls"], "google_cloud.enable_tls"
            )
        if gcloud.get("ca_cert"):
            self.google_cloud__ca_cert = gcloud["ca_cert"]
        if gcloud.get("client_cert"):
            self.google_cloud__client_cert = gcloud["client_cert"]
        if gcloud.get("client_key"):
            self.google_cloud__client_key = gcloud["client_key"]
        if gcloud.get("mqtt_username"):
            self.google_cloud__mqtt_username = gcloud["mqtt_username"]
        if gcloud.get("mqtt_password"):
            self.google_cloud__mqtt_password = gcloud["mqtt_password"]
        if gcloud.get("jwt_expires_minutes") is not None:
            self.google_cloud__jwt_expires_minutes = _require_int(
                gcloud["jwt_expires_minutes"], "google_cloud.jwt_expires_minutes"
            )
        if gcloud.get("offline_buffer_max_messages") is not None:
            self.google_cloud__offline_buffer_max_messages = _require_int(
                gcloud["offline_buffer_max_messages"], "google_cloud.offline_buffer_max_messages"
            )

        modbus = _require_section_dict(ext_conf, "modbus")
        if modbus.get("stale_timeout_sec") is not None:
            self.modbus__stale_timeout_sec = _require_finite_number(
                modbus["stale_timeout_sec"], "modbus.stale_timeout_sec"
            )
        if modbus.get("crc_check") is not None:
            if not isinstance(modbus["crc_check"], str):
                raise GatewayConfigError("modbus.crc_check must be a string")
            self.modbus__crc_check = modbus["crc_check"].strip().lower()
        if modbus.get("poll_mode") is not None:
            if not isinstance(modbus["poll_mode"], str):
                raise GatewayConfigError("modbus.poll_mode must be a string")
            self.modbus__poll_mode = modbus["poll_mode"].strip().lower()
        if "transport" in modbus:
            if not isinstance(modbus["transport"], str):
                raise GatewayConfigError("modbus.transport must be a string")
            self.modbus__transport = modbus["transport"].strip().lower()
        if modbus.get("poll_host"):
            self.modbus__poll_host = str(modbus["poll_host"])
        if modbus.get("poll_port") is not None:
            self.modbus__poll_port = _require_int(modbus["poll_port"], "modbus.poll_port")
        if modbus.get("poll_interval_sec") is not None:
            self.modbus__poll_interval_sec = _require_finite_number(
                modbus["poll_interval_sec"], "modbus.poll_interval_sec"
            )
        if modbus.get("poll_timeout_sec") is not None:
            self.modbus__poll_timeout_sec = _require_finite_number(
                modbus["poll_timeout_sec"], "modbus.poll_timeout_sec"
            )
        if "serial_port" in modbus and modbus["serial_port"] is not None:
            self.modbus__serial_port = _require_non_empty_str(
                modbus["serial_port"], "modbus.serial_port"
            )
        if "serial_ports" in modbus:
            raw_ports = modbus["serial_ports"]
            if not isinstance(raw_ports, dict):
                raise GatewayConfigError("modbus.serial_ports must be an object")
            validated_ports = {}
            for port_key, port_path in raw_ports.items():
                clean_key = _require_non_empty_str(port_key, "modbus.serial_ports key")
                clean_path = _require_non_empty_str(port_path, f"modbus.serial_ports.{clean_key}")
                validated_ports[clean_key] = clean_path
            self.modbus__serial_ports = validated_ports
        if "baudrate" in modbus:
            self.modbus__baudrate = _require_int(modbus["baudrate"], "modbus.baudrate")
        if "bytesize" in modbus:
            self.modbus__bytesize = _require_int(modbus["bytesize"], "modbus.bytesize")
        if "parity" in modbus:
            if not isinstance(modbus["parity"], str):
                raise GatewayConfigError("modbus.parity must be a string")
            self.modbus__parity = modbus["parity"].strip().upper()
        if "stopbits" in modbus:
            self.modbus__stopbits = _require_int(modbus["stopbits"], "modbus.stopbits")
        if "rs485_mode" in modbus:
            self.modbus__rs485_mode = _require_bool(modbus["rs485_mode"], "modbus.rs485_mode")

        site = _require_section_dict(ext_conf, "site_details")
        if site.get("name"):
            self.site_details__name = site["name"]
        if site.get("registry_id"):
            self.site_details__registry_id = site["registry_id"]
            self._explicit_registry_id = True
        if site.get("gateway_id"):
            self.site_details__gateway_id = site["gateway_id"]
        if site.get("serial_no"):
            self.site_details__serial_no = str(site["serial_no"])
        if site.get("localnet"):
            self.site_details__localnet = site["localnet"]
        if isinstance(site.get("hardware"), dict):
            self.site_details__hardware = dict(site["hardware"])
        if "gateway_points_enabled" in site:
            self.site_details__gateway_points_enabled = _require_bool(
                site["gateway_points_enabled"], "site_details.gateway_points_enabled"
            )
        if site.get("proxy_ids") is not None:
            raw_proxies = site["proxy_ids"]
            if not isinstance(raw_proxies, dict):
                raise GatewayConfigError("site_details.proxy_ids must be an object")
            self.site_details__devices = {
                key: (dict(val) if isinstance(val, dict) else val)
                for key, val in raw_proxies.items()
            }

        env_setup = _require_section_dict(ext_conf, "environment_setup")
        if env_setup.get("udmi_site_model_path"):
            self.udmi_site_model_path = env_setup["udmi_site_model_path"]
        if env_setup.get("resources_path"):
            self.resources_path = env_setup["resources_path"]
        if env_setup.get("state_dir"):
            self.state_dir = env_setup["state_dir"]

    def _parse_args_configuration(self, args=None):
        """Read command line arguments and override settings provided in config files."""
        if not args:
            return

        broker_enabled = _arg_value(args, "internal_broker__enabled")
        if broker_enabled is not None:
            self.internal_broker__enabled = _require_bool(
                broker_enabled, "--internal-broker-enabled"
            )
        broker_host = _arg_value(args, "internal_broker__mqtt_bridge_hostname")
        if broker_host is not None:
            self.internal_broker__mqtt_bridge_hostname = broker_host
        broker_port = _arg_value(args, "internal_broker__mqtt_bridge_port")
        if broker_port is not None:
            self.internal_broker__mqtt_bridge_port = _require_int(
                broker_port, "-internal-broker-port"
            )

        iot_provider = _arg_value(args, "google_cloud__iot_provider")
        if iot_provider is not None:
            self.google_cloud__iot_provider = iot_provider
        project_id = _arg_value(args, "google_cloud__project_id")
        if project_id is not None:
            self.google_cloud__project_id = project_id
        cloud_host = _arg_value(args, "google_cloud__mqtt_bridge_hostname")
        if cloud_host is not None:
            self.google_cloud__mqtt_bridge_hostname = cloud_host
        cloud_port = _arg_value(args, "google_cloud__mqtt_bridge_port")
        if cloud_port is not None:
            self.google_cloud__mqtt_bridge_port = _require_int(cloud_port, "-google-cloud-port")
        if _arg_value(args, "no_cloud_tls"):
            self.google_cloud__enable_tls = False
        ca_cert = _arg_value(args, "google_cloud__ca_cert")
        if ca_cert is not None:
            self.google_cloud__ca_cert = ca_cert

        poll_mode = _arg_value(args, "modbus__poll_mode")
        if poll_mode is not None:
            self.modbus__poll_mode = str(poll_mode).strip().lower()
        transport = _arg_value(args, "modbus__transport")
        if transport is not None:
            self.modbus__transport = str(transport).strip().lower()
        poll_host = _arg_value(args, "modbus__poll_host")
        if poll_host is not None:
            self.modbus__poll_host = poll_host
        poll_port = _arg_value(args, "modbus__poll_port")
        if poll_port is not None:
            self.modbus__poll_port = _require_int(poll_port, "--modbus-poll-port")
        poll_interval = _arg_value(args, "modbus__poll_interval_sec")
        if poll_interval is not None:
            self.modbus__poll_interval_sec = _require_finite_number(
                poll_interval, "--modbus-poll-interval"
            )
        serial_port = _arg_value(args, "modbus__serial_port")
        if serial_port is not None:
            self.modbus__serial_port = _require_non_empty_str(serial_port, "--modbus-serial-port")
        baudrate = _arg_value(args, "modbus__baudrate")
        if baudrate is not None:
            self.modbus__baudrate = _require_int(baudrate, "--modbus-baudrate")
        bytesize = _arg_value(args, "modbus__bytesize")
        if bytesize is not None:
            self.modbus__bytesize = _require_int(bytesize, "--modbus-bytesize")
        parity = _arg_value(args, "modbus__parity")
        if parity is not None:
            self.modbus__parity = str(parity).strip().upper()
        stopbits = _arg_value(args, "modbus__stopbits")
        if stopbits is not None:
            self.modbus__stopbits = _require_int(stopbits, "--modbus-stopbits")
        rs485_mode = _arg_value(args, "modbus__rs485_mode")
        if rs485_mode is not None:
            self.modbus__rs485_mode = _require_bool(rs485_mode, "--modbus-rs485")

        gateway_points = _arg_value(args, "site_details__gateway_points_enabled")
        if gateway_points is not None:
            self.site_details__gateway_points_enabled = _require_bool(
                gateway_points, "--gateway-points"
            )

        site_model_path = _arg_value(args, "udmi_site_model_path")
        if site_model_path is not None:
            self.udmi_site_model_path = site_model_path
        resources_path = _arg_value(args, "resources_path")
        if resources_path is not None:
            self.resources_path = resources_path
        state_dir = _arg_value(args, "state_dir")
        if state_dir is not None:
            self.state_dir = state_dir

        self._parse_site_cli_overrides(args)

    def _parse_site_cli_overrides(self, args=None):
        """CLI values win over both the module config and the site model cloud_iot_config.json."""
        if not args:
            return
        cloud_region = _arg_value(args, "google_cloud__cloud_region")
        if cloud_region is not None:
            self.google_cloud__cloud_region = cloud_region
            self._explicit_cloud_region = True
        site_name = _arg_value(args, "site_details__name")
        if site_name is not None:
            self.site_details__name = site_name
        registry_id = _arg_value(args, "site_details__registry_id")
        if registry_id is not None:
            self.site_details__registry_id = registry_id
            self._explicit_registry_id = True
        gateway_id = _arg_value(args, "site_details__gateway_id")
        if gateway_id is not None:
            self.site_details__gateway_id = gateway_id
        serial_no = _arg_value(args, "site_details__serial_no")
        if serial_no is not None:
            self.site_details__serial_no = str(serial_no)

    def _validate(self):
        port_checks = [
            ("google_cloud.mqtt_bridge_port", self.google_cloud__mqtt_bridge_port),
            ("modbus.poll_port", self.modbus__poll_port),
        ]
        if self.internal_broker__enabled:
            port_checks.insert(
                0, ("internal_broker.mqtt_bridge_port", self.internal_broker__mqtt_bridge_port)
            )
        for field, port in port_checks:
            _require_int(port, field)
            if not 1 <= port <= 65535:
                raise GatewayConfigError(f"{field} must be between 1 and 65535, got {port}")
        if not 10 <= self.google_cloud__jwt_expires_minutes <= 1440:
            raise GatewayConfigError("google_cloud.jwt_expires_minutes must be between 10 and 1440")
        if self.google_cloud__offline_buffer_max_messages < 0:
            raise GatewayConfigError("google_cloud.offline_buffer_max_messages must be >= 0")
        if self.modbus__crc_check not in CRC_CHECK_MODES:
            raise GatewayConfigError(
                f"modbus.crc_check must be one of {CRC_CHECK_MODES}, got '{self.modbus__crc_check}'"
            )
        if self.modbus__poll_mode not in POLL_MODES:
            raise GatewayConfigError(
                f"modbus.poll_mode must be one of {POLL_MODES}, got '{self.modbus__poll_mode}'"
            )
        if self.modbus__transport not in MODBUS_TRANSPORTS:
            raise GatewayConfigError(
                f"modbus.transport must be one of {MODBUS_TRANSPORTS}, got '{self.modbus__transport}'"
            )
        _require_int(self.modbus__baudrate, "modbus.baudrate")
        if self.modbus__baudrate not in VALID_BAUDRATES:
            raise GatewayConfigError(
                f"modbus.baudrate must be one of {VALID_BAUDRATES}, got {self.modbus__baudrate}"
            )
        _require_int(self.modbus__bytesize, "modbus.bytesize")
        if self.modbus__bytesize not in VALID_BYTESIZES:
            raise GatewayConfigError(
                f"modbus.bytesize must be one of {VALID_BYTESIZES}, got {self.modbus__bytesize}"
            )
        if self.modbus__parity not in VALID_PARITIES:
            raise GatewayConfigError(
                f"modbus.parity must be one of {VALID_PARITIES}, got '{self.modbus__parity}'"
            )
        _require_int(self.modbus__stopbits, "modbus.stopbits")
        if self.modbus__stopbits not in VALID_STOPBITS:
            raise GatewayConfigError(
                f"modbus.stopbits must be one of {VALID_STOPBITS}, got {self.modbus__stopbits}"
            )
        if self.modbus__poll_interval_sec <= 0:
            raise GatewayConfigError("modbus.poll_interval_sec must be > 0")
        if self.modbus__poll_timeout_sec <= 0:
            raise GatewayConfigError("modbus.poll_timeout_sec must be > 0")
        if self.modbus__stale_timeout_sec <= 0:
            raise GatewayConfigError("modbus.stale_timeout_sec must be > 0")
        if self.google_cloud__sample_rate_set <= 0:
            raise GatewayConfigError("google_cloud.sample_rate_set must be > 0")

        seen_slaves = {}
        for device_id, details in self.site_details__devices.items():
            if not isinstance(details, dict):
                raise GatewayConfigError(f"site_details.proxy_ids.{device_id} must be an object")
            for key in ("type", "modbus_slave_id"):
                if key not in details:
                    raise GatewayConfigError(f"site_details.proxy_ids.{device_id} is missing '{key}'")
            slave = _require_int(
                details["modbus_slave_id"], f"site_details.proxy_ids.{device_id}.modbus_slave_id"
            )
            if not 0 <= slave <= 255:
                raise GatewayConfigError(f"modbus_slave_id {slave} of {device_id} is out of range")
            if slave in seen_slaves:
                raise GatewayConfigError(
                    f"modbus_slave_id {slave} is used by both {seen_slaves[slave]} and {device_id}"
                )
            seen_slaves[slave] = device_id

        if self.modbus__poll_mode != "off" and self.modbus__transport == "rtu":
            if not self.site_details__devices:
                raise GatewayConfigError(
                    "modbus.transport='rtu' polling requires at least one device in site_details.proxy_ids"
                )
            has_default_serial = (
                isinstance(self.modbus__serial_port, str) and bool(self.modbus__serial_port.strip())
            )
            for device_id, details in self.site_details__devices.items():
                dev_port = details.get("port")
                has_dev_port = isinstance(dev_port, str) and bool(dev_port.strip())
                if not has_dev_port and not has_default_serial:
                    raise GatewayConfigError(
                        f"Proxy device '{device_id}' requires 'port' or modbus.serial_port "
                        "when modbus.transport='rtu'"
                    )

        if not self.internal_broker__enabled and self.modbus__poll_mode == "off":
            self.logger.warning(
                "internal_broker.enabled is false while modbus.poll_mode is 'off': "
                "no Modbus telemetry source is enabled"
            )

    def _print_configuration(self):
        poll_target = (
            f"rtu:{self.modbus__serial_port or 'per-device'}@{self.modbus__baudrate}"
            if self.modbus__transport == "rtu"
            else f"tcp:{self.modbus__poll_host}:{self.modbus__poll_port}"
        )
        self.logger.info(
            "Configuration: internal broker enabled=%s %s:%s (topic=%s, tls=%s), cloud %s %s:%s "
            "(tls=%s, project=%s, region=%s, buffer=%s), registry %s, gateway %s (points=%s), "
            "proxies %s, site model %s, state dir %s, stale timeout %ss, crc %s, poll %s (%s every %ss)",
            self.internal_broker__enabled,
            self.internal_broker__mqtt_bridge_hostname,
            self.internal_broker__mqtt_bridge_port,
            self.internal_broker__topic,
            self.internal_broker__enable_tls,
            self.google_cloud__iot_provider,
            self.google_cloud__mqtt_bridge_hostname,
            self.google_cloud__mqtt_bridge_port,
            self.google_cloud__enable_tls,
            self.google_cloud__project_id,
            self.google_cloud__cloud_region,
            self.google_cloud__offline_buffer_max_messages,
            self.site_details__registry_id,
            self.site_details__gateway_id,
            self.site_details__gateway_points_enabled,
            sorted(self.site_details__devices),
            self.udmi_site_model_path,
            self.state_dir,
            self.modbus__stale_timeout_sec,
            self.modbus__crc_check,
            self.modbus__poll_mode,
            poll_target,
            self.modbus__poll_interval_sec,
        )
