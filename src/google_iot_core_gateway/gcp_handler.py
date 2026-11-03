import argparse
import json
import os
import queue
import time
from queue import Empty

from google_iot_core_gateway import ROOT_DIR
from google_iot_core_gateway.gcp_publisher import GoogleIoTCoreMQTTPublisher
from google_iot_core_gateway.internal_broker_subscriber.internal_broker_subscriber import (
    MosquittoMQTTSubscriber,
)
from google_iot_core_gateway.modbus_gw.modbus_to_json import modbus_to_json
from google_iot_core_gateway.udmi_handler.udmi_handler import UDMIHandler
from google_iot_core_gateway.utils.certificates_handler import (
    get_gateway_private_key,
    get_google_root_ca,
)
from google_iot_core_gateway.utils.config_handler import ConfigHandler
from google_iot_core_gateway.utils.log import setup_logger


def get_google_cloud_cmd_line_parser():
    """
    Return parser for the Google Cloud & UDMI command-line args.
    """
    parser = argparse.ArgumentParser(add_help=False)

    group = parser.add_argument_group("Cloud settings")
    group.add_argument(
        "-google-cloud-config-file",
        dest="google_cloud_config_file",
        metavar="CONFIG_FILE",
        help="Google Cloud Configuration file. Defaults to resources/config-google-gateway.json",
    )
    group.add_argument(
        "-iot-provider",
        "--iot-provider",
        dest="google_cloud__iot_provider",
        type=str,
        choices=["gbos", "clearblade", "gcp", "mqtt", "local"],
        help="IoT MQTT provider mode ('gbos' for ClearBlade/GCP IoT Core, 'mqtt' for local UDMI broker)",
    )
    group.add_argument(
        "-google-cloud-region",
        dest="google_cloud__cloud_region",
        type=str,
        metavar="REGION",
        help="Overwrite Google Cloud Region",
    )
    group.add_argument(
        "-google-cloud-project-id",
        dest="google_cloud__project_id",
        type=str,
        metavar="PROJECT_ID",
        help="Overwrite Google Cloud Project ID",
    )
    group.add_argument(
        "-google-cloud-hostname",
        dest="google_cloud__mqtt_bridge_hostname",
        type=str,
        metavar="HOSTNAME",
        help="Overwrite Google Cloud MQTT Bridge Hostname",
    )
    group.add_argument(
        "-google-cloud-port",
        dest="google_cloud__mqtt_bridge_port",
        type=int,
        metavar="PORT",
        help="Overwrite Google Cloud MQTT Bridge Port",
    )
    group.add_argument(
        "--no-cloud-tls",
        dest="no_cloud_tls",
        action="store_true",
        help="Disable TLS on upstream MQTT connection (for plain local MQTT test brokers)",
    )
    group.add_argument(
        "-cloud-ca-cert",
        dest="google_cloud__ca_cert",
        type=str,
        metavar="CA_CERT",
        help="Custom CA certificate path for upstream MQTT connection",
    )

    group = parser.add_argument_group("Site Details settings")
    group.add_argument(
        "-site-details-name",
        dest="site_details__name",
        type=str,
        metavar="NAME",
        help="Overwrite Site Registry Name",
    )
    group.add_argument(
        "-site-details-registry-id",
        dest="site_details__registry_id",
        type=str,
        metavar="REGISTRY_ID",
        help="Overwrite Site Registry ID",
    )
    group.add_argument(
        "-site-details-gateway-id",
        dest="site_details__gateway_id",
        type=str,
        metavar="GATEWAY_ID",
        help="Overwrite Google Cloud Gateway ID",
    )
    group.add_argument(
        "-s",
        "-serial-no",
        "--serial-no",
        dest="site_details__serial_no",
        type=str,
        metavar="SERIAL_NO",
        help="Gateway device serial number reported in UDMI state.system.serial_no",
    )

    group = parser.add_argument_group("Environment settings")
    group.add_argument(
        "-udmi-site-model-path",
        dest="udmi_site_model_path",
        type=str,
        metavar="PATH",
        help="Overwrite UDMI Site Model path",
    )
    group.add_argument(
        "-resources-path",
        dest="resources_path",
        type=str,
        metavar="PATH",
        help="Overwrite resources path",
    )

    return parser


def parse_command_line_args(args=None, parents=None):
    """Parse command-line arguments when module is invoked standalone."""
    parser = argparse.ArgumentParser(allow_abbrev=False, add_help=True, parents=parents or [])
    parser.add_argument(
        "-internal-broker-hostname",
        dest="internal_broker__mqtt_bridge_hostname",
        type=str,
        metavar="HOSTNAME",
        help="Overwrite Internal Broker Hostname",
    )
    parser.add_argument(
        "-internal-broker-port",
        dest="internal_broker__mqtt_bridge_port",
        type=int,
        metavar="PORT",
        help="Overwrite Internal Broker Port",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose_level",
        default=None,
        help="Turn on console DEBUG mode [-v 2]",
    )

    parsed_args, _unknown_args = parser.parse_known_args(args)
    return parsed_args


def _resolve_local_mqtt_tls_files(config):
    """Auto-discover UDMI site model reflector/ca.crt and device client cert when using iot_provider=mqtt."""
    ca_cert = config.google_cloud__ca_cert
    client_cert = config.google_cloud__client_cert
    client_key = config.google_cloud__client_key

    if config.google_cloud__iot_provider in ("mqtt", "local"):
        if not ca_cert:
            reflector_ca = os.path.join(config.udmi_site_model_path, "reflector", "ca.crt")
            if os.path.exists(reflector_ca):
                ca_cert = reflector_ca
        device_dir = os.path.join(
            config.udmi_site_model_path, "devices", config.site_details__gateway_id
        )
        if not client_cert:
            for name in ("rsa_private.crt", "ec_private.crt"):
                cand = os.path.join(device_dir, name)
                if os.path.exists(cand):
                    client_cert = cand
                    break
        if not client_key and client_cert:
            for name in ("rsa_private.pem", "ec_private.pem"):
                cand = os.path.join(device_dir, name)
                if os.path.exists(cand):
                    client_key = cand
                    break

    return get_google_root_ca(config.resources_path, custom_ca_cert=ca_cert), client_cert, client_key


def _get_google_iot_core_publisher(logger, config):
    """Set up Google IoT Core / ClearBlade / Local UDMI MQTT publisher client."""
    key_required = config.google_cloud__iot_provider not in ("mqtt", "local")
    private_key_file_path, encryption_algorithm = get_gateway_private_key(
        logger,
        config.udmi_site_model_path,
        config.site_details__gateway_id,
        required=key_required,
    )
    ca_cert, client_cert, client_key = _resolve_local_mqtt_tls_files(config)

    return GoogleIoTCoreMQTTPublisher(
        logger,
        config.site_details__devices,
        cloud_region=config.google_cloud__cloud_region,
        project_id=config.google_cloud__project_id,
        registry_id=config.site_details__registry_id,
        gateway_id=config.site_details__gateway_id,
        mqtt_bridge_hostname=config.google_cloud__mqtt_bridge_hostname,
        mqtt_bridge_port=config.google_cloud__mqtt_bridge_port,
        private_key_file=private_key_file_path,
        ca_cert=ca_cert,
        jwt_signing_algorithm=encryption_algorithm,
        iot_provider=config.google_cloud__iot_provider,
        enable_tls=config.google_cloud__enable_tls,
        client_cert=client_cert,
        client_key=client_key,
        mqtt_username=config.google_cloud__mqtt_username,
        mqtt_password=config.google_cloud__mqtt_password,
    )


def _get_udmi_handler(logger, config):
    """Initialize UDMIHandler with both the gateway device and all proxied Modbus devices."""
    udmi_handler = UDMIHandler(
        logger,
        config.resources_path,
        config.udmi_site_model_path,
        default_sample_rate_sec=config.google_cloud__sample_rate_set,
    )

    for device_id in list(config.site_details__devices.keys()):
        details = config.site_details__devices[device_id]
        modbus_slave_id = details["modbus_slave_id"]
        device_type = details["type"]
        proxy_serial = details.get("serial_no")
        device_added = udmi_handler.add_device_to_dict(
            modbus_slave_id, device_id, device_type, serial_no=proxy_serial
        )
        if not device_added:
            del config.site_details__devices[device_id]

    udmi_handler.register_gateway(
        gateway_id=config.site_details__gateway_id,
        proxy_ids=list(config.site_details__devices.keys()),
        serial_no=config.site_details__serial_no,
        localnet_config=config.site_details__localnet,
    )

    return udmi_handler


def prepare_google_cloud_environment(logger, config):
    """Set up UDMI handler and MQTT publisher client."""
    udmi_handler = _get_udmi_handler(logger, config)
    google_iot_core_publisher = _get_google_iot_core_publisher(logger, config)
    return google_iot_core_publisher, udmi_handler


def _build_slave_to_type_map(udmi_handler: UDMIHandler) -> dict:
    return {
        int(slave_id): dev["device_type"]
        for slave_id, dev in udmi_handler.devices.items()
        if "device_type" in dev
    }


def process_payloads(logger, google_iot_core_queue, udmi_handler, max_batch=64):
    """
    Drain up to `max_batch` Modbus RTU payloads from the internal broker queue
    and update proxied device properties in `udmi_handler`.
    """
    slave_to_type = _build_slave_to_type_map(udmi_handler)
    processed = 0

    while processed < max_batch:
        try:
            raw_item = google_iot_core_queue.get_nowait()
        except Empty:
            break

        processed += 1
        try:
            frame_msg = json.loads(raw_item)
            rtu_request = bytes.fromhex(frame_msg["rtu_request"])
            rtu_response = bytes.fromhex(frame_msg["rtu_response"])

            decoded_json = modbus_to_json(
                rtu_request,
                rtu_response,
                slave_to_type=slave_to_type,
                dbo_maps=udmi_handler._modbus_dbo_map,
            )
        except Exception as ex:
            logger.error(f"Exception decoding internal Modbus queue item: {ex}")
            continue

        if not decoded_json:
            continue

        payload = json.loads(decoded_json)
        modbus_slave_id = str(payload["slave_id"])
        if modbus_slave_id not in udmi_handler.devices:
            logger.debug(
                f"Modbus slave '{modbus_slave_id}' is not configured in site_details; ignoring."
            )
            continue

        error = payload.get("error")
        if error is not None:
            udmi_handler.set_modbus_poll_error(modbus_slave_id, error)
            continue

        udmi_handler.set_modbus_poll_error(modbus_slave_id, None)
        device_type = udmi_handler.devices[modbus_slave_id]["device_type"]
        function_code = payload.get("fc")
        data = payload.get("data") or {}

        if function_code in (3, 4) and isinstance(data, dict):
            for registry, value in data.items():
                udmi_handler.update_device_properties(
                    modbus_slave_id, device_type, registry, value
                )

    return processed


def process_downlink_configs(logger, google_iot_core_publisher, udmi_handler):
    """Drain all received downlink UDMI `config` messages and apply them immediately."""
    processed = 0
    while True:
        try:
            device_id, raw_payload = google_iot_core_publisher.config_queue.get_nowait()
        except Empty:
            break

        processed += 1
        logger.info(f"Processing downlink UDMI config for '{device_id}'")
        udmi_handler.handle_config(device_id, raw_payload)

        # If gateway config updated proxy_ids, synchronize MQTT proxy subscriptions/attachments
        if device_id == udmi_handler.gateway_id:
            gw_dev = udmi_handler.devices_by_id.get(device_id) or {}
            google_iot_core_publisher.sync_proxy_devices(gw_dev.get("configured_proxy_ids"))

    return processed


def publish_due_udmi_messages(logger, google_iot_core_publisher, udmi_handler):
    """
    Publish due `events/system`, `events/discovery`, dirty `state`, and scheduled
    `events/pointset` messages for the gateway and all active proxied devices.

    `events/system` and `events/discovery` are flushed BEFORE `state` so config logs and
    self-enumeration payloads arrive at the UDMI sequencer ahead of state synchronization.
    """
    now_mono = time.monotonic()
    for device_id in udmi_handler.get_active_device_ids():
        # 1. System events (logs & metrics)
        sys_event_payload = udmi_handler.pop_due_system_event_payload(device_id, now_mono=now_mono)
        if sys_event_payload is not None:
            logger.info(f"Publishing 'events/system' for device '{device_id}'")
            google_iot_core_publisher.publish(device_id, sys_event_payload, topic="events/system")

        # 2. Self-enumeration discovery events
        for disc_payload in udmi_handler.pop_due_discovery_events(device_id):
            logger.info(f"Publishing 'events/discovery' for device '{device_id}'")
            google_iot_core_publisher.publish(
                device_id, disc_payload, topic="events/discovery"
            )

        # 3. Device state (only when dirty and past 2s throttle)
        state_payload = udmi_handler.pop_due_state_payload(device_id, now_mono=now_mono)
        if state_payload is not None:
            logger.info(f"Publishing 'state' for device '{device_id}'")
            google_iot_core_publisher.publish(device_id, state_payload, topic="state")

        # 4. Pointset telemetry events (on per-device sample_rate_sec / sample_limit_sec schedule)
        pointset_payload = udmi_handler.pop_due_pointset_event_payload(device_id, now_mono=now_mono)
        if pointset_payload is not None:
            logger.info(f"Publishing 'events/pointset' for device '{device_id}'")
            google_iot_core_publisher.publish(
                device_id, pointset_payload, topic="events/pointset"
            )


def start_google_iot_core_gateway(logger, args, root_dir=None, stop_event=None):
    """
    Main loop establishing connections to the internal MXcloudgate broker and upstream
    MQTT bridge, processing Modbus telemetry and downlink UDMI configs, and publishing
    UDMI 1.5 state and event messages.
    """
    config = ConfigHandler(logger, args, root_dir or ROOT_DIR)

    google_iot_core_queue = queue.Queue(maxsize=500)
    int_broker_subscriber = MosquittoMQTTSubscriber(
        logger,
        google_iot_core_queue,
        config.internal_broker__mqtt_bridge_hostname,
        config.internal_broker__mqtt_bridge_port,
        config.internal_broker__trusted_root_ca,
        config.internal_broker__x509_certificate,
        config.internal_broker__private_key,
        config.internal_broker__tls_insecure_set,
        config.internal_broker__enable_tls,
    )
    int_broker_subscriber.run()

    google_iot_core_publisher, udmi_handler = prepare_google_cloud_environment(logger, config)

    try:
        while stop_event is None or not stop_event.is_set():
            # Wait up to 100ms for an incoming downlink config so config updates react sub-second
            try:
                first_cfg = google_iot_core_publisher.config_queue.get(timeout=0.1)
                device_id, raw_payload = first_cfg
                logger.info(f"Processing downlink UDMI config for '{device_id}'")
                udmi_handler.handle_config(device_id, raw_payload)
                if device_id == udmi_handler.gateway_id:
                    gw_dev = udmi_handler.devices_by_id.get(device_id) or {}
                    google_iot_core_publisher.sync_proxy_devices(
                        gw_dev.get("configured_proxy_ids")
                    )
            except Empty:
                pass

            process_downlink_configs(logger, google_iot_core_publisher, udmi_handler)
            process_payloads(logger, google_iot_core_queue, udmi_handler)

            if not google_iot_core_publisher.is_connection_open():
                continue

            publish_due_udmi_messages(logger, google_iot_core_publisher, udmi_handler)
    finally:
        int_broker_subscriber.stop()
        google_iot_core_publisher.close()


def start_standalone_google_iot_core_gateway(assigned_args=None, logger=None, stop_event=None):
    """Standalone entry point for `python -m google_iot_core_gateway`."""
    args = parse_command_line_args(
        args=assigned_args, parents=[get_google_cloud_cmd_line_parser()]
    )
    if not logger:
        logger = setup_logger()
    start_google_iot_core_gateway(logger, args, stop_event=stop_event)
