#!/usr/bin/env python3
import json
import os
import sys

from google_iot_core_gateway import ROOT_DIR
from google_iot_core_gateway.utils.log import update_logger_verbose_level


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

        self.google_cloud__iot_provider = "gbos"
        self.google_cloud__cloud_region = "europe-west1"
        self.google_cloud__project_id = "moxa01-iot-core"
        self.google_cloud__sample_rate_set = 1800
        self.google_cloud__mqtt_bridge_hostname = "mqtt.googleapis.com"
        self.google_cloud__mqtt_bridge_port = 8883
        self.google_cloud__enable_tls = True
        self.google_cloud__ca_cert = None
        self.google_cloud__client_cert = None
        self.google_cloud__client_key = None
        self.google_cloud__mqtt_username = None
        self.google_cloud__mqtt_password = None

        self.site_details__name = "KGX-1"
        self.site_details__registry_id = "KGX-1"
        self.site_details__gateway_id = "CGW-1"
        self.site_details__serial_no = None
        self.site_details__localnet = None
        self.site_details__devices = {
            "EM-1": {
                "id": "",
                "type": "simulator",
                "modbus_slave_id": 1,
            }
        }

        self.udmi_site_model_path = "/home/moxa/udmi_site_model"
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
        self._print_configuration()

    def _read_ext_config(self, config_file=None):
        """Read JSON configuration file."""
        if config_file is None:
            config_file = self._google_cloud_config_file
        try:
            self.logger.info(f"*********** Reading External Config: {config_file} ***********")
            with open(config_file, "r", encoding="utf-8") as json_data_file:
                cfg_obj = json.load(json_data_file)
                self.logger.debug(f"  ******* External Config:\n  {cfg_obj} *******")
                return cfg_obj
        except (FileNotFoundError, IOError, OSError) as e:
            self.logger.error(f"Invalid path to the config file: {config_file}")
            self.logger.error(e)
            return None

    def _parse_udmi_site_model_configuration(self):
        """Read UDMI Site Model cloud_iot_config.json for registry/region details."""
        self.logger.info("*********** Parse UDMI Site Model Configuration ***********")
        udmi_site_model_config = os.path.join(
            self.udmi_site_model_path, "cloud_iot_config.json"
        )
        ext_conf = self._read_ext_config(config_file=udmi_site_model_config)

        if not ext_conf:
            self.logger.error("*********** Empty UDMI Site Model Configuration! ***********")
            sys.exit(1)

        if ext_conf.get("cloud_region"):
            self.google_cloud__cloud_region = ext_conf["cloud_region"]
        if ext_conf.get("site_name"):
            self.site_details__name = ext_conf["site_name"]
        if ext_conf.get("registry_id"):
            self.site_details__registry_id = ext_conf["registry_id"]

    def _parse_module_configuration(self):
        """Read config-google-gateway.json for Internal Broker, Cloud, and Modbus proxy devices."""
        self.logger.info("*********** Parse Module Configuration ***********")
        ext_conf = self._read_ext_config()

        if not ext_conf:
            self.logger.error("*********** Empty Module Configuration! ***********")
            sys.exit(1)

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

        site = ext_conf.get("site_details") or {}
        if site.get("gateway_id"):
            self.site_details__gateway_id = site["gateway_id"]
        if site.get("serial_no"):
            self.site_details__serial_no = str(site["serial_no"])
        if site.get("localnet"):
            self.site_details__localnet = site["localnet"]
        if site.get("proxy_ids") is not None:
            self.site_details__devices = dict(site["proxy_ids"])

        env_setup = ext_conf.get("environment_setup") or {}
        if env_setup.get("udmi_site_model_path"):
            self.udmi_site_model_path = env_setup["udmi_site_model_path"]
        if env_setup.get("resources_path"):
            self.resources_path = env_setup["resources_path"]

    def _parse_args_configuration(self, args=None):
        """Read command line arguments and override settings provided in config files."""
        self.logger.info("*********** Parse args Configuration ***********")
        if not args:
            self.logger.info("*********** Empty args Configuration! Skipping! ***********")
            return

        if getattr(args, "internal_broker__mqtt_bridge_hostname", None) is not None:
            self.internal_broker__mqtt_bridge_hostname = args.internal_broker__mqtt_bridge_hostname
        if getattr(args, "internal_broker__mqtt_bridge_port", None) is not None:
            self.internal_broker__mqtt_bridge_port = int(args.internal_broker__mqtt_bridge_port)

        if getattr(args, "google_cloud__iot_provider", None) is not None:
            self.google_cloud__iot_provider = args.google_cloud__iot_provider
        if getattr(args, "google_cloud__cloud_region", None) is not None:
            self.google_cloud__cloud_region = args.google_cloud__cloud_region
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

        self._parse_site_cli_overrides(args)

    def _parse_site_cli_overrides(self, args=None):
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

    def _print_configuration(self):
        self.logger.info(
            f"  internal_broker__mqtt_bridge_hostname: {self.internal_broker__mqtt_bridge_hostname}"
        )
        self.logger.info(
            f"  internal_broker__mqtt_bridge_port: {self.internal_broker__mqtt_bridge_port}"
        )
        self.logger.info(f"  internal_broker__enable_tls: {self.internal_broker__enable_tls}")
        self.logger.info(f"  google_cloud__iot_provider: {self.google_cloud__iot_provider}")
        self.logger.info(f"  google_cloud__cloud_region: {self.google_cloud__cloud_region}")
        self.logger.info(f"  google_cloud__project_id: {self.google_cloud__project_id}")
        self.logger.info(
            f"  google_cloud__mqtt_bridge_hostname: {self.google_cloud__mqtt_bridge_hostname}"
        )
        self.logger.info(f"  google_cloud__mqtt_bridge_port: {self.google_cloud__mqtt_bridge_port}")
        self.logger.info(f"  google_cloud__enable_tls: {self.google_cloud__enable_tls}")
        self.logger.info(f"  site_details__name: {self.site_details__name}")
        self.logger.info(f"  site_details__registry_id: {self.site_details__registry_id}")
        self.logger.info(f"  site_details__gateway_id: {self.site_details__gateway_id}")
        self.logger.info(f"  site_details__serial_no: {self.site_details__serial_no}")
        self.logger.info(f"  site_details__devices: {self.site_details__devices}")
        self.logger.info(f"  udmi_site_model_path: {self.udmi_site_model_path}")
        self.logger.info(f"  resources_path: {self.resources_path}")
        self.logger.info("*********** Parse Configuration Successful! ***********")
