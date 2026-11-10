# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

import argparse
import json
import os
import queue
import threading
import time
from queue import Empty

import paho.mqtt.client as mqtt

from google_iot_core_gateway import ROOT_DIR
from google_iot_core_gateway.errors import EXIT_FATAL, EXIT_OK, EXIT_RESTART, GatewayConfigError
from google_iot_core_gateway.gcp_publisher import GoogleIoTCoreMQTTPublisher
from google_iot_core_gateway.internal_broker_subscriber.internal_broker_subscriber import (
    MosquittoMQTTSubscriber,
)
from google_iot_core_gateway.modbus_gw.modbus_to_json import modbus_to_json
from google_iot_core_gateway.runner import run_gateway_process
from google_iot_core_gateway.udmi_handler.udmi_handler import UDMIHandler
from google_iot_core_gateway.utils.certificates_handler import (
    get_gateway_private_key,
    get_google_root_ca,
)
from google_iot_core_gateway.utils.config_handler import ConfigHandler
from google_iot_core_gateway.utils.log import setup_logger
from google_iot_core_gateway.utils.persistent_store import PersistentStore

SUMMARY_INTERVAL_SEC = 600.0
RESTART_FLUSH_TIMEOUT_SEC = 3.0
_LOG_THROTTLE = {}


def _log_throttled(key, level_fn, message, interval_sec=300.0):
    now = time.monotonic()
    last = _LOG_THROTTLE.get(key)
    if last is None or now - last >= interval_sec:
        _LOG_THROTTLE[key] = now
        level_fn(message)


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
        choices=["iot_core", "gcp", "mqtt", "local"],
        help="Upstream MQTT mode: 'iot_core' for a Cloud IoT Core compatible bridge (/devices/... "
        "topics, JWT), 'mqtt' for a UDMI MQTT broker (/r/<registry>/d/... topics)",
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
        help="Gateway serial number, used when the hardware does not expose one",
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
    group.add_argument(
        "-state-dir",
        "--state-dir",
        dest="state_dir",
        type=str,
        metavar="PATH",
        help="Directory for persistent data (restart counter). Default: systemd StateDirectory, "
        "/var/lib/moxa-gcloud-udmi or ~/.local/state/moxa-gcloud-udmi",
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


def _resolve_tls_files(config):
    """Return (ca_cert, ca_is_explicit, client_cert, client_key) for the upstream connection.

    For local UDMI brokers (`iot_provider` mqtt/local) the site model's `reflector/ca.crt` and the
    gateway's `rsa_private.crt`/`.pem` client certificate are used when present.
    """
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

    ca_path, ca_is_explicit = get_google_root_ca(config.resources_path, custom_ca_cert=ca_cert)
    return ca_path, ca_is_explicit, client_cert, client_key


def _get_google_iot_core_publisher(logger, config, autostart=False):
    """Set up the upstream MQTT publisher client (IoT Core compatible bridge or UDMI MQTT broker)."""
    key_required = config.google_cloud__iot_provider not in ("mqtt", "local")
    private_key_file_path, encryption_algorithm = get_gateway_private_key(
        logger,
        config.udmi_site_model_path,
        config.site_details__gateway_id,
        required=key_required,
    )
    ca_cert, ca_is_explicit, client_cert, client_key = _resolve_tls_files(config)

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
        ca_cert_required=ca_is_explicit,
        jwt_signing_algorithm=encryption_algorithm,
        iot_provider=config.google_cloud__iot_provider,
        enable_tls=config.google_cloud__enable_tls,
        client_cert=client_cert,
        client_key=client_key,
        mqtt_username=config.google_cloud__mqtt_username,
        mqtt_password=config.google_cloud__mqtt_password,
        jwt_expires_minutes=config.google_cloud__jwt_expires_minutes,
        autostart=autostart,
    )


def _get_udmi_handler(logger, config, restart_count=1):
    """Initialize UDMIHandler with both the gateway device and all proxied Modbus devices."""
    udmi_handler = UDMIHandler(
        logger,
        config.resources_path,
        config.udmi_site_model_path,
        default_sample_rate_sec=config.google_cloud__sample_rate_set,
        stale_timeout_sec=config.modbus__stale_timeout_sec,
    )

    for device_id in list(config.site_details__devices.keys()):
        details = config.site_details__devices[device_id]
        device_added = udmi_handler.add_device_to_dict(
            details["modbus_slave_id"],
            device_id,
            details["type"],
            serial_no=details.get("serial_no"),
            port=details.get("port"),
        )
        if not device_added:
            logger.error(f"Proxy device '{device_id}' could not be registered and is skipped")
            del config.site_details__devices[device_id]

    udmi_handler.register_gateway(
        gateway_id=config.site_details__gateway_id,
        proxy_ids=list(config.site_details__devices.keys()),
        serial_no=config.site_details__serial_no,
        localnet_config=config.site_details__localnet,
        restart_count=restart_count,
        hardware=config.site_details__hardware,
    )
    return udmi_handler


def prepare_google_cloud_environment(logger, config, restart_count=1):
    """Set up UDMI handler and MQTT publisher client (not yet connected)."""
    udmi_handler = _get_udmi_handler(logger, config, restart_count=restart_count)
    google_iot_core_publisher = _get_google_iot_core_publisher(logger, config)
    return google_iot_core_publisher, udmi_handler


def process_payloads(logger, google_iot_core_queue, udmi_handler, max_batch=64, strict_crc=True):
    """
    Drain up to `max_batch` MXcloudgate Modbus RTU messages from the internal broker queue and
    apply them to the proxied devices.
    """
    slave_to_type = udmi_handler.get_meter_types()
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
                dbo_maps=udmi_handler.dbo_maps,
                strict_crc=strict_crc,
            )
            if not decoded_json:
                continue
            payload = json.loads(decoded_json)
            if payload.get("fc") not in (3, 4):
                continue
            udmi_handler.record_modbus_payload(payload)
        except Exception as ex:  # noqa: BLE001 - one bad message must never stop the gateway
            _log_throttled(
                ("bad_frame", type(ex).__name__),
                logger.warning,
                f"Ignoring malformed MXcloudgate message ({type(ex).__name__}: {str(ex)[:200]})",
            )

    return processed


def _handle_downlink_config(logger, google_iot_core_publisher, udmi_handler, device_id, raw_payload):
    logger.debug(f"Processing downlink UDMI config for '{device_id}'")
    udmi_handler.handle_config(device_id, raw_payload)
    if device_id == udmi_handler.gateway_id:
        google_iot_core_publisher.sync_proxy_devices(udmi_handler.get_configured_proxy_ids())


def process_downlink_configs(logger, google_iot_core_publisher, udmi_handler):
    """Drain all received downlink UDMI `config` messages and apply them immediately."""
    processed = 0
    while True:
        try:
            device_id, raw_payload = google_iot_core_publisher.config_queue.get_nowait()
        except Empty:
            break
        processed += 1
        _handle_downlink_config(logger, google_iot_core_publisher, udmi_handler, device_id, raw_payload)
    return processed


def process_gateway_errors(google_iot_core_publisher, udmi_handler):
    """Surface cloud `errors` topic messages (e.g. failed proxy attach) in the gateway state."""
    errors = google_iot_core_publisher.drain_gateway_errors()
    for device_id, payload, generation in errors:
        udmi_handler.record_gateway_error(device_id, payload, generation)
    return len(errors)


def _publish(logger, publisher, stats, device_id, payload, topic):
    info = publisher.publish(device_id, payload, topic=topic)
    rc = getattr(info, "rc", mqtt.MQTT_ERR_SUCCESS)
    if rc == mqtt.MQTT_ERR_SUCCESS:
        if stats is not None:
            stats[topic] = stats.get(topic, 0) + 1
    else:
        _log_throttled(
            ("publish_rc", topic, rc),
            logger.warning,
            f"MQTT client did not accept '{topic}' for {device_id}: {mqtt.error_string(rc)}",
        )
    return info, rc


def publish_due_udmi_messages(logger, google_iot_core_publisher, udmi_handler, stats=None):
    """
    Publish due `events/system`, `events/discovery`, changed `state`, and scheduled
    `events/pointset` messages for the gateway and all active proxied devices.

    `events/system` and `events/discovery` are flushed BEFORE `state` so config logs and
    self-enumeration payloads arrive ahead of the state update. Returns the list of
    MQTTMessageInfo objects for the published messages.
    """
    infos = []
    now_mono = time.monotonic()
    for device_id in udmi_handler.get_active_device_ids():
        sys_event_payload = udmi_handler.pop_due_system_event_payload(device_id, now_mono=now_mono)
        if sys_event_payload is not None:
            info, _rc = _publish(
                logger, google_iot_core_publisher, stats, device_id, sys_event_payload, "events/system"
            )
            infos.append(info)

        for disc_payload in udmi_handler.pop_due_discovery_events(device_id):
            info, _rc = _publish(
                logger, google_iot_core_publisher, stats, device_id, disc_payload, "events/discovery"
            )
            infos.append(info)

        state_payload = udmi_handler.pop_due_state_payload(device_id, now_mono=now_mono)
        if state_payload is not None:
            info, rc = _publish(
                logger, google_iot_core_publisher, stats, device_id, state_payload, "state"
            )
            infos.append(info)
            if rc == mqtt.MQTT_ERR_SUCCESS:
                logger.info(f"Published state for '{device_id}'")
            else:
                udmi_handler.state_publish_failed(device_id)

        pointset_payload = udmi_handler.pop_due_pointset_event_payload(device_id, now_mono=now_mono)
        if pointset_payload is not None:
            info, _rc = _publish(
                logger, google_iot_core_publisher, stats, device_id, pointset_payload, "events/pointset"
            )
            infos.append(info)
    return infos


def _wait_for_delivery(infos, timeout_sec):
    deadline = time.monotonic() + timeout_sec
    for info in infos:
        while time.monotonic() < deadline:
            try:
                if info.is_published():
                    break
            except (RuntimeError, ValueError):
                break
            time.sleep(0.05)


def run_gateway_loop(logger, config, google_iot_core_publisher, udmi_handler, google_iot_core_queue, stop_event=None):
    """Main loop. Returns EXIT_OK on shutdown request or EXIT_RESTART on a UDMI restart request."""
    strict_crc = config.modbus__crc_check == "strict"
    last_generation = google_iot_core_publisher.connection_generation
    stats = {}
    next_summary = time.monotonic() + SUMMARY_INTERVAL_SEC

    while stop_event is None or not stop_event.is_set():
        # Wait up to 100ms for an incoming downlink config so config updates react sub-second
        try:
            device_id, raw_payload = google_iot_core_publisher.config_queue.get(timeout=0.1)
            _handle_downlink_config(logger, google_iot_core_publisher, udmi_handler, device_id, raw_payload)
        except Empty:
            pass

        process_downlink_configs(logger, google_iot_core_publisher, udmi_handler)
        process_gateway_errors(google_iot_core_publisher, udmi_handler)
        process_payloads(logger, google_iot_core_queue, udmi_handler, strict_crc=strict_crc)
        udmi_handler.tick()
        google_iot_core_publisher.maintain()

        generation = google_iot_core_publisher.connection_generation
        if generation != last_generation:
            # New MQTT session: anything sent on the old one may be lost, so send state again;
            # proxies are re-attached, so earlier cloud attach errors no longer apply.
            last_generation = generation
            udmi_handler.clear_attach_errors(before_generation=generation)
            udmi_handler.force_republish_all()

        if google_iot_core_publisher.is_connected():
            infos = publish_due_udmi_messages(
                logger, google_iot_core_publisher, udmi_handler, stats=stats
            )
        else:
            infos = []

        if udmi_handler.restart_requested:
            if google_iot_core_publisher.is_connected():
                infos += publish_due_udmi_messages(
                    logger, google_iot_core_publisher, udmi_handler, stats=stats
                )
            _wait_for_delivery(infos, RESTART_FLUSH_TIMEOUT_SEC)
            logger.warning("Restart requested via UDMI system.operation.mode; exiting for restart")
            return EXIT_RESTART

        if time.monotonic() >= next_summary:
            next_summary = time.monotonic() + SUMMARY_INTERVAL_SEC
            logger.info(
                f"Last {int(SUMMARY_INTERVAL_SEC)} s: connected={google_iot_core_publisher.is_connected()} "
                f"published={dict(sorted(stats.items()))}"
            )
            stats.clear()
    return EXIT_OK


def start_google_iot_core_gateway(logger, args, root_dir=None, stop_event=None):
    """
    Run the gateway: connect to the internal MXcloudgate broker and the upstream MQTT bridge,
    process Modbus telemetry and downlink UDMI configs, and publish UDMI messages.

    Returns a process exit code (EXIT_OK, EXIT_FATAL or EXIT_RESTART).
    """
    try:
        config = ConfigHandler(logger, args, root_dir or ROOT_DIR)
        restart_count = PersistentStore(logger, config.state_dir).increment_restart_count()
        google_iot_core_publisher, udmi_handler = prepare_google_cloud_environment(
            logger, config, restart_count=restart_count
        )
    except GatewayConfigError as exc:
        logger.error(f"Fatal configuration error: {exc}")
        return EXIT_FATAL

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
    google_iot_core_publisher.start()

    try:
        return run_gateway_loop(
            logger,
            config,
            google_iot_core_publisher,
            udmi_handler,
            google_iot_core_queue,
            stop_event=stop_event,
        )
    finally:
        int_broker_subscriber.stop()
        google_iot_core_publisher.close()


def start_standalone_google_iot_core_gateway(assigned_args=None, logger=None, stop_event=None):
    """Standalone entry point for `python -m google_iot_core_gateway` (same behaviour as main.py)."""
    args = parse_command_line_args(
        args=assigned_args, parents=[get_google_cloud_cmd_line_parser()]
    )
    if not logger:
        logger = setup_logger()
    if stop_event is None and threading.current_thread() is threading.main_thread():
        # Same process model as main.py: the gateway runs in a worker thread that never receives
        # SIGINT/SIGTERM, and this thread turns them into a clean shutdown.
        stop_event = threading.Event()
        return run_gateway_process(
            logger, lambda: start_google_iot_core_gateway(logger, args, stop_event=stop_event), stop_event
        )
    return start_google_iot_core_gateway(logger, args, stop_event=stop_event)


__all__ = [
    "EXIT_FATAL",
    "EXIT_OK",
    "EXIT_RESTART",
    "get_google_cloud_cmd_line_parser",
    "process_downlink_configs",
    "process_gateway_errors",
    "process_payloads",
    "publish_due_udmi_messages",
    "run_gateway_loop",
    "start_google_iot_core_gateway",
]
