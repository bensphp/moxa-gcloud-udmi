# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""End-to-end tests against a real local Mosquitto broker (skipped if mosquitto is missing)."""

import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import types

import paho.mqtt.client as mqtt
import pytest

from conftest import REPO_ROOT, RESOURCES_DIR, find_free_port, write_site_model
from google_iot_core_gateway.errors import EXIT_FATAL, EXIT_OK, EXIT_RESTART
from google_iot_core_gateway.gcp_handler import run_gateway_loop
from google_iot_core_gateway.gcp_publisher import GoogleIoTCoreMQTTPublisher
from google_iot_core_gateway.internal_broker_subscriber.internal_broker_subscriber import (
    MosquittoMQTTSubscriber,
)
from google_iot_core_gateway.udmi_handler.udmi_handler import UDMIHandler
import mxcloudgate_simulator as sim

MOSQUITTO = "/usr/sbin/mosquitto"
pytestmark = pytest.mark.skipif(not os.path.exists(MOSQUITTO), reason="mosquitto not installed")
PREFIX = "/r/UK-LON-GLAB/d"


def _wait_port(port, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} not ready")


def _start_broker(tmp_path, port):
    conf = tmp_path / f"mosquitto-{port}.conf"
    store = tmp_path / f"mosquitto-{port}-store"
    store.mkdir(exist_ok=True)
    # Persistence keeps the observer's session (and queued QoS 1 messages) across broker restarts.
    conf.write_text(
        f"listener {port} 127.0.0.1\nallow_anonymous true\n"
        f"persistence true\npersistence_location {store}/\n",
        encoding="utf-8",
    )
    proc = subprocess.Popen([MOSQUITTO, "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _wait_port(port)
    return proc


class Observer:
    """Test-side MQTT client playing the cloud: records every device message, sends configs."""

    def __init__(self, port):
        self._history = []
        self._cond = threading.Condition()
        self.ready = threading.Event()
        if hasattr(mqtt, "CallbackAPIVersion"):
            self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id="observer", clean_session=False)
        else:
            self.client = mqtt.Client(client_id="observer", clean_session=False)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = lambda *a: self.ready.clear()
        self.client.on_subscribe = lambda *a: self.ready.set()
        self.client.on_message = self._on_message
        self.client.reconnect_delay_set(1, 2)
        self.client.connect("127.0.0.1", port, 30)
        self.client.loop_start()
        assert self.ready.wait(5)

    def _on_connect(self, client, _userdata, _flags, rc):
        if rc == 0:
            client.subscribe(f"{PREFIX}/#", qos=1)

    def _on_message(self, _client, _userdata, msg):
        with self._cond:
            self._history.append((msg.topic, msg.payload.decode()))
            self._cond.notify_all()

    def mark(self) -> int:
        with self._cond:
            return len(self._history)

    def send_config(self, device, config):
        # Retained, like a cloud registry that delivers the latest config on subscribe.
        self.client.publish(f"{PREFIX}/{device}/config", json.dumps(config), qos=1, retain=True)

    def wait_for(self, predicate, timeout=15.0, since=0):
        deadline = time.monotonic() + timeout
        index = since
        with self._cond:
            while True:
                while index < len(self._history):
                    topic, payload = self._history[index]
                    index += 1
                    if predicate(topic, payload):
                        return topic, payload
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError("expected MQTT message not received")
                self._cond.wait(remaining)

    def close(self):
        self.client.loop_stop()
        self.client.disconnect()


def _state_of(device, condition=lambda s: True):
    def _predicate(topic, payload):
        return topic == f"{PREFIX}/{device}/state" and condition(json.loads(payload))
    return _predicate


def _publish_frames(observer, slaves=(1,)):
    for slave in slaves:
        for req, resp in sim.build_slave_frames(slave, 1):
            observer.client.publish("MXcloudgate", json.dumps({"rtu_request": req.hex(), "rtu_response": resp.hex()}), qos=0)


def _base_config(ts, **blocks):
    cfg = {"version": "1.5.2", "timestamp": ts, "system": {"min_loglevel": 200}}
    cfg.update(blocks)
    return cfg


@pytest.fixture
def broker(tmp_path):
    port = find_free_port()
    proc = _start_broker(tmp_path, port)
    state = {"proc": proc, "port": port}
    yield state
    if state["proc"].poll() is None:
        state["proc"].terminate()
        state["proc"].wait(timeout=5)


def test_gateway_loop_end_to_end_and_state_resent_after_reconnect(tmp_path, broker, logger):
    port = broker["port"]
    site_dir = write_site_model(tmp_path)
    handler = UDMIHandler(logger, RESOURCES_DIR, str(site_dir), default_sample_rate_sec=1.0, config_wait_timeout_sec=1.0)
    handler.add_device_to_dict(1, "EM-11", "PM5561", port="ttyM0")
    handler.register_gateway("CGW-2", proxy_ids=["EM-11"], serial_no="CGW2-E2E")

    observer = Observer(port)
    publisher = GoogleIoTCoreMQTTPublisher(
        logger, {"EM-11": {}}, project_id="local", cloud_region="europe-west1", registry_id="UK-LON-GLAB",
        gateway_id="CGW-2", private_key_file=None, ca_cert=None, mqtt_bridge_hostname="127.0.0.1",
        mqtt_bridge_port=port, iot_provider="mqtt", enable_tls=False,
    )
    internal_q = queue.Queue(maxsize=500)
    subscriber = MosquittoMQTTSubscriber(logger, internal_q, host="127.0.0.1", port=port)
    subscriber.run()
    stop = threading.Event()
    config = types.SimpleNamespace(modbus__crc_check="strict")
    result = {}
    loop = threading.Thread(
        target=lambda: result.setdefault("rc", run_gateway_loop(logger, config, publisher, handler, internal_q, stop)),
        daemon=True,
    )
    loop.start()
    try:
        assert publisher.wait_for_connection(10)
        observer.wait_for(lambda t, p: t == f"{PREFIX}/EM-11/attach")
        observer.send_config("CGW-2", _base_config("2026-11-04T11:00:00Z", gateway={"proxy_ids": ["EM-11"]}))
        observer.send_config("EM-11", _base_config(
            "2026-11-04T11:00:00Z", gateway={"target": {"family": "modbus"}},
            pointset={"sample_rate_sec": 1, "points": {"line1_neutral_voltage_sensor": {"ref": "3/3028/2?type=FLOAT32"}}},
        ))
        deadline = time.monotonic() + 10
        event = None
        while event is None and time.monotonic() < deadline:
            _publish_frames(observer)
            try:
                event = observer.wait_for(lambda t, p: t == f"{PREFIX}/EM-11/events/pointset", timeout=1.0)
            except AssertionError:
                pass
        assert event is not None
        assert json.loads(event[1])["points"]["line1_neutral_voltage_sensor"]["present_value"] > 200
        observer.wait_for(_state_of("CGW-2", lambda s: s["system"]["last_config"] == "2026-11-04T11:00:00Z"))
        observer.wait_for(_state_of("EM-11", lambda s: s["system"]["serial_no"] == "52110011"))

        # Broker restart: the gateway reconnects on its own and re-sends state.
        mark = observer.mark()
        generation = publisher.connection_generation
        broker["proc"].terminate()
        broker["proc"].wait(timeout=5)
        broker["proc"] = _start_broker(tmp_path, port)
        deadline = time.monotonic() + 20
        while publisher.connection_generation == generation and time.monotonic() < deadline:
            time.sleep(0.1)
        assert publisher.connection_generation > generation
        assert observer.ready.wait(10)
        observer.wait_for(_state_of("CGW-2"), timeout=15, since=mark)
        observer.wait_for(_state_of("EM-11"), timeout=15, since=mark)
    finally:
        stop.set()
        loop.join(timeout=5)
        subscriber.stop()
        publisher.close()
        observer.close()
    assert result.get("rc") == EXIT_OK


def _write_gateway_config(tmp_path, port, site_dir, state_dir):
    path = tmp_path / "gateway-config.json"
    path.write_text(json.dumps({
        "internal_broker": {"mqtt_bridge_hostname": "127.0.0.1", "mqtt_bridge_port": port},
        "google_cloud": {"iot_provider": "mqtt", "mqtt_bridge_hostname": "127.0.0.1", "mqtt_bridge_port": port,
                         "enable_tls": False, "sample_rate_set": 5},
        "site_details": {"gateway_id": "CGW-2", "serial_no": "CGW2-E2E",
                         "proxy_ids": {"EM-11": {"type": "PM5561", "modbus_slave_id": 1, "port": "ttyM0"}}},
        "environment_setup": {"udmi_site_model_path": str(site_dir), "resources_path": RESOURCES_DIR,
                              "state_dir": str(state_dir)},
    }), encoding="utf-8")
    return path


def _start_main(config_path):
    return subprocess.Popen(
        [sys.executable, "-B", str(REPO_ROOT / "src" / "main.py"), "-c", str(config_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(config_path.parent),
    )


def test_system_mode_restart_really_restarts(tmp_path, broker):
    port = broker["port"]
    site_dir = write_site_model(tmp_path)
    state_dir = tmp_path / "state"
    config_path = _write_gateway_config(tmp_path, port, site_dir, state_dir)
    observer = Observer(port)
    proc = _start_main(config_path)
    try:
        observer.send_config("CGW-2", _base_config("2026-11-04T12:00:00Z", system={"operation": {"mode": "active"}}))
        observer.wait_for(_state_of("CGW-2", lambda s: s["system"]["operation"] == {
            "operational": True, "last_start": s["system"]["operation"]["last_start"],
            "restart_count": 1, "mode": "active"}), timeout=20)
        observer.send_config("CGW-2", _base_config("2026-11-04T12:00:05Z", system={"operation": {"mode": "restart"}}))
        assert proc.wait(timeout=20) == EXIT_RESTART
        assert json.loads((state_dir / "persistent_data.json").read_text())["restart_count"] == 1

        # The supervisor (systemd Restart=always) starts the gateway again.
        proc = _start_main(config_path)
        restarted = observer.wait_for(_state_of("CGW-2", lambda s: s["system"]["operation"]["restart_count"] == 2), timeout=20)
        assert json.loads(restarted[1])["system"]["operation"]["mode"] == "initial"
        observer.send_config("CGW-2", _base_config("2026-11-04T12:00:10Z", system={"operation": {"mode": "active"}}))
        observer.wait_for(_state_of("CGW-2", lambda s: s["system"]["operation"]["mode"] == "active"), timeout=20)
        proc.terminate()
        assert proc.wait(timeout=20) == EXIT_OK
    finally:
        if proc.poll() is None:
            proc.kill()
        observer.close()


def test_fatal_configuration_errors_exit_non_zero(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-B", str(REPO_ROOT / "src" / "main.py"), "-c", str(tmp_path / "missing.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False,
    )
    assert proc.returncode == EXIT_FATAL
