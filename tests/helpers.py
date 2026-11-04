# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Helpers shared by the test modules (importable via conftest's sys.path setup)."""

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from google_iot_core_gateway.gcp_publisher import GoogleIoTCoreMQTTPublisher
from google_iot_core_gateway.udmi_handler.udmi_handler import LEVEL_INFO

V = "1.5.2"


def config(ts, **blocks):
    cfg = {"version": V, "timestamp": ts, "system": {"min_loglevel": LEVEL_INFO}}
    cfg.update(blocks)
    return json.dumps(cfg)


def em11_config(ts="2026-11-04T10:00:00Z", points=None, target=None, rate=10):
    return config(
        ts,
        gateway={"target": target or {"family": "modbus"}},
        localnet={"families": {"modbus": {}}},
        pointset={
            "sample_rate_sec": rate,
            "points": points
            or {
                "line1_neutral_voltage_sensor": {"ref": "3/3028/2?type=FLOAT32"},
                "frequency_sensor": {"ref": "3/3110/2?type=FLOAT32"},
            },
        },
    )


def frame(regs, slave=1, start=3028, qty=2, unavailable=None):
    return {
        "slave_id": slave,
        "fc": 3,
        "start_register": start,
        "quantity": qty,
        "data": {str(k): v for k, v in regs.items()},
        "unavailable": {str(k): "N/A(ffc00000)" for k in (unavailable or [])},
        "error": None,
    }


def exception_reply(code, start, qty, slave=1):
    return {
        "slave_id": slave,
        "fc": 3,
        "start_register": start,
        "quantity": qty,
        "data": None,
        "unavailable": {},
        "error": f"Modbus exception code 0x{code:02x}",
        "error_kind": "exception",
        "exception_code": code,
    }


def state_of(handler, device="EM-11"):
    return json.loads(handler.get_state_payload(device))


class RecordingClient:
    def __init__(self):
        self.calls = []

    def subscribe(self, topic, qos=0):
        self.calls.append(("subscribe", topic))

    def unsubscribe(self, topic):
        self.calls.append(("unsubscribe", topic))

    def publish(self, topic, payload, qos=0):
        self.calls.append(("publish", topic))

    def topics(self, kind):
        return [topic for call, topic in self.calls if call == kind]


def make_publisher(logger, provider="mqtt", **kwargs):
    defaults = dict(
        logger=logger,
        connected_devices={"EM-11": {}, "EM-12": {}},
        project_id="proj",
        cloud_region="europe-west1",
        registry_id="UK-LON-GLAB",
        gateway_id="CGW-2",
        private_key_file=None,
        ca_cert=None,
        mqtt_bridge_hostname="127.0.0.1",
        mqtt_bridge_port=1,
        iot_provider=provider,
        enable_tls=False,
        autostart=False,
    )
    defaults.update(kwargs)
    return GoogleIoTCoreMQTTPublisher(**defaults)


def write_rsa_key(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "rsa_private.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(path)
