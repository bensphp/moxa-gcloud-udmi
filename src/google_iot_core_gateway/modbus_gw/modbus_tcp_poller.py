# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Optional built-in Modbus TCP poller feeding the gateway's RTU frame queue.

Disabled by default (`modbus.poll_mode = "off"`). In `"fallback"` mode it polls only identity
registers and configured point blocks not yet supplied by an external poller; in `"active"` mode
it polls all configured point blocks and periodically refreshes identity registers.
"""

import json
import queue
import socket
import struct
import threading
import time

from google_iot_core_gateway.modbus_gw.modbus_to_json import append_modbus_crc16

POLL_MODES = ("off", "fallback", "active")
LOG_THROTTLE_SEC = 300.0


def build_modbus_tcp_fc3_request(
    tx_id: int, unit_id: int, start_register_1based: int, quantity: int
) -> bytes:
    """Build a Modbus TCP MBAP + FC03 Read Holding Registers ADU."""
    pdu = struct.pack(">BHH", 3, int(start_register_1based) - 1, int(quantity))
    mbap = struct.pack(">HHHB", tx_id & 0xFFFF, 0, len(pdu) + 1, int(unit_id) & 0xFF)
    return mbap + pdu


def _recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    chunks = []
    remaining = nbytes
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("Modbus TCP peer closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_modbus_tcp_response(
    sock: socket.socket, expected_tx_id: int, expected_unit_id: int
) -> bytes:
    """Read one Modbus TCP ADU and return `unit_id + PDU` (without CRC)."""
    mbap = _recv_exact(sock, 7)
    tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", mbap)
    if proto_id != 0:
        raise ValueError(f"Unexpected Modbus TCP protocol id {proto_id}")
    if length < 2 or length > 256:
        raise ValueError(f"Invalid Modbus TCP length {length}")
    pdu = _recv_exact(sock, length - 1)
    if tx_id != (expected_tx_id & 0xFFFF):
        raise ValueError(f"Modbus TCP transaction id mismatch ({tx_id} != {expected_tx_id & 0xFFFF})")
    if unit_id != (expected_unit_id & 0xFF):
        raise ValueError(f"Modbus TCP unit id mismatch ({unit_id} != {expected_unit_id & 0xFF})")
    return bytes([unit_id]) + pdu


class ModbusTCPPoller:
    """Background Modbus TCP poller emitting MXcloudgate JSON frames into the decoder queue."""

    def __init__(
        self,
        logger,
        google_iot_core_queue,
        udmi_handler,
        host: str = "127.0.0.1",
        port: int = 502,
        mode: str = "fallback",
        interval_sec: float = 10.0,
        timeout_sec: float = 2.0,
    ):
        self.logger = logger
        self.google_iot_core_queue = google_iot_core_queue
        self.udmi_handler = udmi_handler
        self.host = host
        self.port = int(port)
        self.mode = str(mode).lower()
        self.interval_sec = max(0.5, float(interval_sec))
        self.timeout_sec = max(0.1, float(timeout_sec))

        self._tx_id = 0
        self._sock = None
        self._sock_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._dropped = 0
        self._last_drop_log = 0.0
        self._last_err_log = 0.0

    def _log_error_throttled(self, message: str):
        now = time.monotonic()
        if now - self._last_err_log >= LOG_THROTTLE_SEC:
            self._last_err_log = now
            self.logger.warning(message)

    def _enqueue_frame(self, rtu_req: bytes, rtu_resp: bytes):
        payload = json.dumps({"rtu_request": rtu_req.hex(), "rtu_response": rtu_resp.hex()})
        try:
            self.google_iot_core_queue.put_nowait(payload)
            return
        except queue.Full:
            pass
        try:
            self.google_iot_core_queue.get_nowait()
        except queue.Empty:
            pass
        try:
            self.google_iot_core_queue.put_nowait(payload)
        except queue.Full:
            pass
        self._dropped += 1
        now = time.monotonic()
        if now - self._last_drop_log >= LOG_THROTTLE_SEC:
            self._last_drop_log = now
            self.logger.warning(
                f"Internal Modbus frame queue full: dropped {self._dropped} oldest frame(s)"
            )

    def _close_socket_locked(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _ensure_socket_locked(self) -> socket.socket:
        if self._sock is None:
            self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout_sec)
            self._sock.settimeout(self.timeout_sec)
        return self._sock

    def poll_once(self) -> int:
        """Execute one polling pass across targets returned by `udmi_handler.get_poll_targets()`."""
        targets = self.udmi_handler.get_poll_targets(
            self.mode, poll_interval_sec=self.interval_sec
        )
        if not targets:
            return 0
        polled = 0
        with self._sock_lock:
            for slave_id, blocks in targets:
                if self._stop_event.is_set():
                    break
                for start_reg, qty in blocks:
                    if self._stop_event.is_set():
                        break
                    self._tx_id = (self._tx_id + 1) & 0xFFFF or 1
                    adu = build_modbus_tcp_fc3_request(self._tx_id, slave_id, start_reg, qty)
                    try:
                        sock = self._ensure_socket_locked()
                        sock.sendall(adu)
                        resp_body = read_modbus_tcp_response(sock, self._tx_id, slave_id)
                    except (OSError, ValueError) as exc:
                        self._close_socket_locked()
                        self._log_error_throttled(
                            f"Modbus TCP poll failed ({self.host}:{self.port}, "
                            f"unit {slave_id} {start_reg}+{qty}): {exc}"
                        )
                        continue
                    rtu_req = append_modbus_crc16(adu[6:])
                    rtu_resp = append_modbus_crc16(resp_body)
                    self._enqueue_frame(rtu_req, rtu_resp)
                    polled += 1
        return polled

    def _run_loop(self):
        while not self._stop_event.is_set():
            self.poll_once()
            if self._stop_event.wait(self.interval_sec):
                break

    def start(self):
        """Start the background Modbus TCP polling thread (no-op if mode is 'off')."""
        if self.mode == "off" or self._thread is not None:
            return
        self.logger.info(
            f"Starting Modbus TCP poller ({self.mode} mode) to {self.host}:{self.port} "
            f"every {self.interval_sec:.1f}s"
        )
        self._thread = threading.Thread(target=self._run_loop, name="modbus-poller", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0):
        """Signal the poller thread to stop and wait up to `timeout` seconds."""
        self._stop_event.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout)
        with self._sock_lock:
            self._close_socket_locked()
