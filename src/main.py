#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Main entry point of Modbus JSON to UDMI Google Cloud IoT Core / ClearBlade Gateway.

Exit codes: 0 = clean shutdown, 1 = fatal error, 192 = restart requested via UDMI
`system.operation.mode` (run under a supervisor such as the bundled systemd unit with
`Restart=always`).
"""

import argparse
import sys
import threading
from pathlib import Path
from typing import List, Optional

_SRC_DIR = str(Path(__file__).resolve().parent)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from google_iot_core_gateway import ROOT_DIR, __version__ as version  # noqa: E402
from google_iot_core_gateway.gcp_handler import (  # noqa: E402
    get_google_cloud_cmd_line_parser,
    start_google_iot_core_gateway,
)
from google_iot_core_gateway.runner import run_gateway_process  # noqa: E402
from google_iot_core_gateway.utils.log import setup_logger  # noqa: E402

logger = setup_logger()


def get_internal_broker_cmd_line_parser() -> argparse.ArgumentParser:
    """Return parser for the Internal Broker command-line args."""
    parser = argparse.ArgumentParser(add_help=False)

    group = parser.add_argument_group("Internal Broker settings")
    group.add_argument(
        "-internal-broker-hostname",
        dest="internal_broker__mqtt_bridge_hostname",
        type=str,
        metavar="HOSTNAME",
        help="Overwrite Internal Broker Hostname. Default ['127.0.0.1']",
    )
    group.add_argument(
        "-internal-broker-port",
        dest="internal_broker__mqtt_bridge_port",
        type=int,
        metavar="PORT",
        help="Overwrite Internal Broker Port. Default [1883]",
    )
    return parser


def parse_main_cmd_line_args(
    args: Optional[List[str]] = None,
    parents: Optional[List[argparse.ArgumentParser]] = None,
) -> argparse.Namespace:
    """Parse the main command-line args (Python 3.9+ compatible type annotations)."""
    parser = argparse.ArgumentParser(
        allow_abbrev=False, add_help=True, parents=parents or []
    )
    parser.add_argument(
        "-c",
        dest="config_file",
        help="Configuration file to use. Defaults to resources/config-google-gateway.json",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose_level",
        default=None,
        help="Turn on console DEBUG mode [-v 2]",
    )
    parser.add_argument("-V", "--version", action="version", version=version)
    return parser.parse_args(args)


def main(argv: Optional[List[str]] = None) -> int:
    parsed_args = parse_main_cmd_line_args(
        args=argv,
        parents=[
            get_google_cloud_cmd_line_parser(),
            get_internal_broker_cmd_line_parser(),
        ],
    )

    stop_event = threading.Event()
    logger.info(f"MQTT Google IoT Core Gateway {version} starting")
    # The gateway runs in a worker thread that never receives SIGINT/SIGTERM; this (main) thread
    # turns them into a clean shutdown (see runner.py).
    return run_gateway_process(
        logger,
        lambda: start_google_iot_core_gateway(logger, parsed_args, ROOT_DIR, stop_event),
        stop_event,
    )


if __name__ == "__main__":
    sys.exit(main())
