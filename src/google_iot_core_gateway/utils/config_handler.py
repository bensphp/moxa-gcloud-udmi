#!/usr/bin/env python3
# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

import json
import os

from google_iot_core_gateway import ROOT_DIR
from google_iot_core_gateway.errors import GatewayConfigError
from google_iot_core_gateway.utils.log import update_logger_verbose_level

SECRET_KEYS = {"mqtt_password", "password", "secret", "token"}
SYSTEM_STATE_DIR = "/var/lib/moxa-gcloud-udmi"
CRC_CHECK_MODES = ("strict", "off")


def redact_secrets(obj):
    """Return a copy of a parsed config with secret values replaced, for logging."""
    if isinstance(obj, dict):
        return {
            key: ("***" if key in SECRET_KEYS and value else redact_secrets(value))
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


class ConfigHandler:

    def __init__(self, logger, args=None, root_dir=None):
        self.logger = logger

        if root_dir is None:
            root_dir = str(ROOT_DIR)
        else:
            root_dir = str(root_dir)

        # Default configuration will be loaded if not specified in config file
        self.internal_broker__mqtt_bridge_hostname = "127.0.0.1"
        self.internal_broker__mqtt_bridge_port = 1883
        self.internal_broker__trusted_root_ca = None
        self.internal_broker__x509_certificate = None
        self.internal_broker__private_key = None
        self.internal_broker__tls_insecure_set = False
        self.internal_broker__enable_tls = False

        self.google_cloud__iot_provider = "iot_core"
        self.google_cloud__cloud_region = "europe-west1"
        self.google_cloud__project_id = "moxa01-iot-core"
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

        self.modbus__stale_timeout_sec = 300.0
        self.modbus__crc_check = "strict"

        # Placeholders (the UDMI reference site name); the site model's cloud_iot_config.json sets them.
        self.site_details__name = "ZZ-TRI-FECTA"
        self.site_details__registry_id = "ZZ-TRI-FECTA"
        self.site_details__gateway_id = "CGW-1"
        self.site_details__serial_no = None
        self.site_details__localnet = None
        self.site_details__hardware = None
        self.site_details__devices = {
            "EM-1": {
                "id": "",
                "type": "simulator",
                "modbus_slave_id": 1,
            }
        }

        self.udmi_site_model_path = "/home/moxa/udmi_site_model"
        self.state_dir = None
        self.resources_path = os.path.join(root_dir, "resources")
        if not os.path.isdir(self.resources_path):
            self.resources_path = root_dir

        if args and getattr(args, "resources_path", None) is not None:
            self.resources_path = args.resources_path

        self._google_cloud_config_file = os.path.join(
            self.resources_path, "config-google-gateway.json"
        )
        if args:
            if getattr(args, "verbose_level", None) is not None:
                update_logger_verbose_level(logger, args.verbose_level)
            if getattr(args, "google_cloud_config_file", None) is not None:
                self._google_cloud_config_file = args.google_cloud_config_file
            elif getattr(args, "config_file", None) is not None:
                self._google_cloud_config_file = args.config_file

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
        self.logger.debug(f"Configuration content: {redact_secrets(cfg_obj)}")
        return cfg_obj

    def _parse_udmi_site_model_configuration(self):
        """Read UDMI Site Model cloud_iot_config.json for registry/region details."""
        udmi_site_model_config = os.path.join(
            self.udmi_site_model_path, "cloud_iot_config.json"
        )
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

        internal = ext_conf.get("internal_broker") or {}
        if internal.get("mqtt_bridge_hostname"):
            self.internal_broker__mqtt_bridge_hostname = internal["mqtt_bridge_hostname"]
        if internal.get("mqtt_bridge_port") is not None:
            self.internal_broker__mqtt_bridge_port = int(internal["mqtt_bridge_port"])
        if internal.get("trusted_root_ca"):
            self.internal_broker__trusted_root_ca = internal["trusted_root_ca"]
        if internal.get("x509_certificate"):
            self.internal_broker__x509_certificate = internal["x509_certificate"]
        if internal.get("private_key"):
            self.internal_broker__private_key = internal["private_key"]
        if "tls_insecure_set" in internal and internal["tls_insecure_set"] is not None:
            self.internal_broker__tls_insecure_set = bool(internal["tls_insecure_set"])
        if "enable_tls" in internal and internal["enable_tls"] is not None:
            self.internal_broker__enable_tls = bool(internal["enable_tls"])

        gcloud = ext_conf.get("google_cloud") or {}
        if gcloud.get("iot_provider"):
            self.google_cloud__iot_provider = gcloud["iot_provider"]
        if gcloud.get("cloud_region"):
            self.google_cloud__cloud_region = gcloud["cloud_region"]
        if gcloud.get("project_id"):
            self.google_cloud__project_id = gcloud["project_id"]
        if gcloud.get("sample_rate_set") is not None:
            self.google_cloud__sample_rate_set = float(gcloud["sample_rate_set"])
        if gcloud.get("mqtt_bridge_hostname"):
            self.google_cloud__mqtt_bridge_hostname = gcloud["mqtt_bridge_hostname"]
        if gcloud.get("mqtt_bridge_port") is not None:
            self.google_cloud__mqtt_bridge_port = int(gcloud["mqtt_bridge_port"])
        if "enable_tls" in gcloud and gcloud["enable_tls"] is not None:
            self.google_cloud__enable_tls = bool(gcloud["enable_tls"])
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
            self.google_cloud__jwt_expires_minutes = int(gcloud["jwt_expires_minutes"])

        modbus = ext_conf.get("modbus") or {}
        if modbus.get("stale_timeout_sec") is not None:
            self.modbus__stale_timeout_sec = float(modbus["stale_timeout_sec"])
        if modbus.get("crc_check") is not None:
            self.modbus__crc_check = str(modbus["crc_check"]).lower()

        site = ext_conf.get("site_details") or {}
        if site.get("gateway_id"):
            self.site_details__gateway_id = site["gateway_id"]
        if site.get("serial_no"):
            self.site_details__serial_no = str(site["serial_no"])
        if site.get("localnet"):
            self.site_details__localnet = site["localnet"]
        if isinstance(site.get("hardware"), dict):
            self.site_details__hardware = site["hardware"]
        if site.get("proxy_ids") is not None:
            self.site_details__devices = dict(site["proxy_ids"])

        env_setup = ext_conf.get("environment_setup") or {}
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

        if getattr(args, "internal_broker__mqtt_bridge_hostname", None) is not None:
            self.internal_broker__mqtt_bridge_hostname = args.internal_broker__mqtt_bridge_hostname
        if getattr(args, "internal_broker__mqtt_bridge_port", None) is not None:
            self.internal_broker__mqtt_bridge_port = int(args.internal_broker__mqtt_bridge_port)

        if getattr(args, "google_cloud__iot_provider", None) is not None:
            self.google_cloud__iot_provider = args.google_cloud__iot_provider
        if getattr(args, "google_cloud__project_id", None) is not None:
            self.google_cloud__project_id = args.google_cloud__project_id
        if getattr(args, "google_cloud__mqtt_bridge_hostname", None) is not None:
            self.google_cloud__mqtt_bridge_hostname = args.google_cloud__mqtt_bridge_hostname
        if getattr(args, "google_cloud__mqtt_bridge_port", None) is not None:
            self.google_cloud__mqtt_bridge_port = int(args.google_cloud__mqtt_bridge_port)
        if getattr(args, "no_cloud_tls", False):
            self.google_cloud__enable_tls = False
        if getattr(args, "google_cloud__ca_cert", None) is not None:
            self.google_cloud__ca_cert = args.google_cloud__ca_cert

        if getattr(args, "udmi_site_model_path", None) is not None:
            self.udmi_site_model_path = args.udmi_site_model_path
        if getattr(args, "resources_path", None) is not None:
            self.resources_path = args.resources_path
        if getattr(args, "state_dir", None) is not None:
            self.state_dir = args.state_dir

        self._parse_site_cli_overrides(args)

    def _parse_site_cli_overrides(self, args=None):
        """CLI values win over both the module config and the site model cloud_iot_config.json."""
        if not args:
            return
        if getattr(args, "google_cloud__cloud_region", None) is not None:
            self.google_cloud__cloud_region = args.google_cloud__cloud_region
        if getattr(args, "site_details__name", None) is not None:
            self.site_details__name = args.site_details__name
        if getattr(args, "site_details__registry_id", None) is not None:
            self.site_details__registry_id = args.site_details__registry_id
        if getattr(args, "site_details__gateway_id", None) is not None:
            self.site_details__gateway_id = args.site_details__gateway_id
        if getattr(args, "site_details__serial_no", None) is not None:
            self.site_details__serial_no = str(args.site_details__serial_no)

    def _validate(self):
        if not 10 <= self.google_cloud__jwt_expires_minutes <= 1440:
            raise GatewayConfigError("google_cloud.jwt_expires_minutes must be between 10 and 1440")
        if self.modbus__crc_check not in CRC_CHECK_MODES:
            raise GatewayConfigError(
                f"modbus.crc_check must be one of {CRC_CHECK_MODES}, got '{self.modbus__crc_check}'"
            )
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
            try:
                slave = int(details["modbus_slave_id"])
            except (TypeError, ValueError) as exc:
                raise GatewayConfigError(
                    f"site_details.proxy_ids.{device_id}.modbus_slave_id must be an integer"
                ) from exc
            if not 0 <= slave <= 255:
                raise GatewayConfigError(f"modbus_slave_id {slave} of {device_id} is out of range")
            if slave in seen_slaves:
                raise GatewayConfigError(
                    f"modbus_slave_id {slave} is used by both {seen_slaves[slave]} and {device_id}"
                )
            seen_slaves[slave] = device_id

    def _print_configuration(self):
        self.logger.info(
            "Configuration: internal broker %s:%s (tls=%s), cloud %s %s:%s (tls=%s, project=%s, "
            "region=%s), registry %s, gateway %s, proxies %s, site model %s, state dir %s, "
            "stale timeout %ss, crc %s",
            self.internal_broker__mqtt_bridge_hostname,
            self.internal_broker__mqtt_bridge_port,
            self.internal_broker__enable_tls,
            self.google_cloud__iot_provider,
            self.google_cloud__mqtt_bridge_hostname,
            self.google_cloud__mqtt_bridge_port,
            self.google_cloud__enable_tls,
            self.google_cloud__project_id,
            self.google_cloud__cloud_region,
            self.site_details__registry_id,
            self.site_details__gateway_id,
            sorted(self.site_details__devices),
            self.udmi_site_model_path,
            self.state_dir,
            self.modbus__stale_timeout_sec,
            self.modbus__crc_check,
        )
