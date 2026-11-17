# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Optional pure-stdlib POSIX RS-485 / serial Modbus RTU poller."""

import errno
import fcntl
import json
import math
import os
import queue
import select
import struct
import termios
import threading
import time

from google_iot_core_gateway.modbus_gw.modbus_to_json import (
    append_modbus_crc16,
    verify_modbus_crc16,
)

MODBUS_TRANSPORTS = ("tcp", "rtu")
VALID_BAUDRATES = (1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200)
VALID_PARITIES = ("N", "E", "O")
VALID_BYTESIZES = (7, 8)
VALID_STOPBITS = (1, 2)
LOG_THROTTLE_SEC = 300.0

_TIOCSRS485 = 0x542F
_BAUDRATE_FLAGS = {
    1200: termios.B1200,
    2400: termios.B2400,
    4800: termios.B4800,
    9600: termios.B9600,
    19200: termios.B19200,
    38400: termios.B38400,
    57600: termios.B57600,
    115200: termios.B115200,
}


def resolve_serial_device(
    port_name, serial_ports_map=None, default_port=None, device_prefix="/dev"
) -> str:
    """Resolve a configured port name (or default) to a serial device or PTY filesystem path."""
    candidate = None
    if port_name and isinstance(serial_ports_map, dict) and port_name in serial_ports_map:
        mapped = serial_ports_map[port_name]
        if mapped is not None and str(mapped).strip():
            candidate = str(mapped).strip()
    if candidate is None:
        raw = port_name if (port_name is not None and str(port_name).strip()) else default_port
        candidate = str(raw).strip() if raw is not None else ""
    if not candidate:
        raise ValueError("No serial port configured for Modbus RTU polling")
    if candidate.startswith("/"):
        return candidate
    return os.path.join(device_prefix or "/dev", candidate)


def build_modbus_rtu_read_request(
    unit_id: int, fc: int, start_register_1based: int, quantity: int
) -> bytes:
    """Build a Modbus RTU FC03/FC04 request frame with trailing 2-byte CRC-16."""
    for name, value in (
        ("unit_id", unit_id),
        ("fc", fc),
        ("start_register_1based", start_register_1based),
        ("quantity", quantity),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer, got {type(value).__name__}")
    if fc not in (3, 4):
        raise ValueError(f"Unsupported Modbus function code {fc}; expected 3 or 4")
    if not (0 <= unit_id <= 255):
        raise ValueError(f"unit_id {unit_id} out of range 0..255")
    if not (1 <= start_register_1based <= 65536):
        raise ValueError(f"start_register_1based {start_register_1based} out of range 1..65536")
    if not (1 <= quantity <= 125):
        raise ValueError(f"quantity {quantity} out of range 1..125")
    pdu = struct.pack(">BBHH", unit_id & 0xFF, fc, start_register_1based - 1, quantity)
    return append_modbus_crc16(pdu)


def _read_exact_fd(fd: int, nbytes: int, deadline: float) -> bytes:
    """Read exactly `nbytes` from a non-blocking FD before `deadline`, or raise."""
    buf = bytearray()
    while len(buf) < nbytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Timed out waiting for Modbus RTU serial response")
        readable, _writable, _exceptional = select.select([fd], [], [], remaining)
        if not readable:
            raise TimeoutError("Timed out waiting for Modbus RTU serial response")
        try:
            chunk = os.read(fd, nbytes - len(buf))
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                continue
            raise
        if not chunk:
            raise OSError("Serial port returned EOF while reading Modbus RTU response")
        buf.extend(chunk)
    return bytes(buf)


def _write_all_fd(fd: int, data: bytes, timeout_sec: float):
    """Write all bytes of `data` to a non-blocking FD within `timeout_sec`."""
    deadline = time.monotonic() + max(0.01, float(timeout_sec))
    view = memoryview(data)
    written = 0
    while written < len(data):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Timed out writing Modbus RTU serial request")
        _readable, writable, _exceptional = select.select([], [fd], [], remaining)
        if not writable:
            raise TimeoutError("Timed out writing Modbus RTU serial request")
        try:
            count = os.write(fd, view[written:])
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                continue
            raise
        if count == 0:
            raise OSError("Serial port write returned 0 bytes")
        written += count


def read_modbus_rtu_response(
    fd: int, expected_unit_id: int, expected_fc: int, expected_qty: int, timeout_sec: float
) -> bytes:
    """Read and validate one Modbus RTU FC03/FC04 normal or exception response frame."""
    if (
        isinstance(expected_unit_id, bool)
        or not isinstance(expected_unit_id, int)
        or not (0 <= expected_unit_id <= 255)
    ):
        raise ValueError(f"expected_unit_id must be 0..255, got {expected_unit_id}")
    if isinstance(expected_fc, bool) or not isinstance(expected_fc, int) or expected_fc not in (3, 4):
        raise ValueError(f"expected_fc must be 3 or 4, got {expected_fc}")
    if isinstance(expected_qty, bool) or not isinstance(expected_qty, int) or expected_qty < 1:
        raise ValueError(f"expected_qty must be >= 1, got {expected_qty}")

    deadline = time.monotonic() + max(0.01, float(timeout_sec))
    header = _read_exact_fd(fd, 3, deadline)
    unit, resp_fc, third = struct.unpack(">BBB", header)

    expected_unit = expected_unit_id & 0xFF
    if unit != expected_unit:
        raise ValueError(f"Modbus RTU unit id mismatch (expected {expected_unit}, got {unit})")

    if resp_fc == (expected_fc | 0x80):
        tail = _read_exact_fd(fd, 2, deadline)
        frame = header + tail
    else:
        if resp_fc != expected_fc:
            raise ValueError(
                f"Modbus RTU function code mismatch (expected {expected_fc}, got {resp_fc})"
            )
        expected_bytes = expected_qty * 2
        if third != expected_bytes:
            raise ValueError(
                f"Modbus RTU byte count mismatch (expected {expected_bytes}, got {third})"
            )
        tail = _read_exact_fd(fd, third + 2, deadline)
        frame = header + tail

    if not verify_modbus_crc16(frame):
        raise ValueError("Modbus RTU response CRC-16 mismatch")
    return frame


class ModbusRTUPoller:
    """Background POSIX serial / RS-485 Modbus RTU poller emitting JSON RTU frame pairs."""

    def __init__(
        self,
        logger,
        google_iot_core_queue,
        udmi_handler,
        mode: str = "active",
        interval_sec: float = 10.0,
        timeout_sec: float = 2.0,
        default_port=None,
        serial_ports=None,
        device_prefix: str = "/dev",
        baudrate: int = 9600,
        bytesize: int = 8,
        parity: str = "N",
        stopbits: int = 1,
        rs485_mode: bool = False,
    ):
        if isinstance(baudrate, bool) or not isinstance(baudrate, int) or baudrate not in VALID_BAUDRATES:
            raise ValueError(f"Invalid baudrate {baudrate}; valid: {VALID_BAUDRATES}")
        if isinstance(bytesize, bool) or not isinstance(bytesize, int) or bytesize not in VALID_BYTESIZES:
            raise ValueError(f"Invalid bytesize {bytesize}; valid: {VALID_BYTESIZES}")
        norm_parity = str(parity).upper()
        if norm_parity not in VALID_PARITIES:
            raise ValueError(f"Invalid parity '{parity}'; valid: {VALID_PARITIES}")
        if isinstance(stopbits, bool) or not isinstance(stopbits, int) or stopbits not in VALID_STOPBITS:
            raise ValueError(f"Invalid stopbits {stopbits}; valid: {VALID_STOPBITS}")
        if (
            isinstance(interval_sec, bool)
            or not isinstance(interval_sec, (int, float))
            or not math.isfinite(interval_sec)
        ):
            raise ValueError(f"Invalid interval_sec {interval_sec}")
        if (
            isinstance(timeout_sec, bool)
            or not isinstance(timeout_sec, (int, float))
            or not math.isfinite(timeout_sec)
        ):
            raise ValueError(f"Invalid timeout_sec {timeout_sec}")

        self.logger = logger
        self.google_iot_core_queue = google_iot_core_queue
        self.udmi_handler = udmi_handler
        self.mode = str(mode or "off").lower()
        self.interval_sec = max(0.05, float(interval_sec))
        self.timeout_sec = max(0.05, float(timeout_sec))
        self.default_port = default_port
        self.serial_ports = dict(serial_ports) if isinstance(serial_ports, dict) else {}
        self.device_prefix = device_prefix or "/dev"
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = norm_parity
        self.stopbits = stopbits
        self.rs485_mode = bool(rs485_mode)

        self._fds = {}
        self._last_tx_end = {}
        self._fd_lock = threading.Lock()
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

    def _configure_serial_fd(self, fd: int, dev_path: str):
        try:
            attrs = termios.tcgetattr(fd)
        except termios.error as exc:
            if exc.args and exc.args[0] == errno.ENOTTY:
                return
            raise

        iflag, oflag, cflag, lflag, _ispeed, _ospeed, cc = attrs
        iflag &= ~(
            termios.IGNBRK
            | termios.BRKINT
            | termios.PARMRK
            | termios.ISTRIP
            | termios.INLCR
            | termios.IGNCR
            | termios.ICRNL
            | termios.IXON
            | termios.IXOFF
            | termios.IXANY
        )
        oflag &= ~termios.OPOST
        lflag &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
        cflag &= ~(termios.CSIZE | termios.PARENB | termios.PARODD | termios.CSTOPB)
        crtscts_flag = vars(termios).get("CRTSCTS", 0)
        if crtscts_flag:
            cflag &= ~crtscts_flag
        cflag |= termios.CLOCAL | termios.CREAD
        cflag |= termios.CS7 if self.bytesize == 7 else termios.CS8
        if self.parity == "E":
            cflag |= termios.PARENB
        elif self.parity == "O":
            cflag |= termios.PARENB | termios.PARODD
        if self.stopbits == 2:
            cflag |= termios.CSTOPB

        speed_flag = _BAUDRATE_FLAGS[self.baudrate]
        cc_copy = list(cc)
        cc_copy[termios.VMIN] = 0
        cc_copy[termios.VTIME] = 0
        termios.tcsetattr(
            fd,
            termios.TCSANOW,
            [iflag, oflag, cflag, lflag, speed_flag, speed_flag, cc_copy],
        )

        if self.rs485_mode:
            rs485_conf = struct.pack("=IIIIIIII", 1, 0, 0, 0, 0, 0, 0, 0)
            try:
                fcntl.ioctl(fd, _TIOCSRS485, rs485_conf)
            except OSError as exc:
                self.logger.debug(f"TIOCSRS485 not supported on {dev_path}: {exc}")

    def _close_fd_locked(self, dev_path: str):
        fd = self._fds.pop(dev_path, None)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def _close_all_fds_locked(self):
        for dev_path in list(self._fds):
            self._close_fd_locked(dev_path)

    def _ensure_fd_locked(self, dev_path: str) -> int:
        fd = self._fds.get(dev_path)
        if fd is not None:
            return fd
        fd = os.open(dev_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            self._configure_serial_fd(fd, dev_path)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        self._fds[dev_path] = fd
        return fd

    def _collect_plan_by_port(self) -> dict:
        by_port = {}
        get_plan = None
        try:
            get_plan = self.udmi_handler.get_poll_plan
        except AttributeError:
            get_plan = None

        if callable(get_plan):
            plan = get_plan(self.mode, poll_interval_sec=self.interval_sec)
            for target in plan or ():
                slave_id = target["slave_id"]
                port_name = target.get("port")
                blocks = target.get("blocks") or ()
                if not blocks:
                    continue
                try:
                    dev_path = resolve_serial_device(
                        port_name,
                        serial_ports_map=self.serial_ports,
                        default_port=self.default_port,
                        device_prefix=self.device_prefix,
                    )
                except ValueError as exc:
                    self._log_error_throttled(f"Skipping Modbus RTU device unit {slave_id}: {exc}")
                    continue
                by_port.setdefault(dev_path, []).append((slave_id, blocks))
        else:
            targets = self.udmi_handler.get_poll_targets(
                self.mode, poll_interval_sec=self.interval_sec
            )
            if targets:
                try:
                    dev_path = resolve_serial_device(
                        None,
                        serial_ports_map=self.serial_ports,
                        default_port=self.default_port,
                        device_prefix=self.device_prefix,
                    )
                except ValueError as exc:
                    self._log_error_throttled(f"Skipping Modbus RTU poll: {exc}")
                    return {}
                for slave_id, blocks in targets:
                    fc3_blocks = [(3, start_reg, qty) for start_reg, qty in blocks]
                    if fc3_blocks:
                        by_port.setdefault(dev_path, []).append((slave_id, fc3_blocks))
        return by_port

    def poll_once(self) -> int:
        """Execute one polling pass grouped per serial device path."""
        by_port = self._collect_plan_by_port()
        if not by_port:
            return 0

        silence_sec = max(0.00175, 3.5 * 11.0 / float(self.baudrate))
        polled = 0
        with self._fd_lock:
            for dev_path, port_targets in by_port.items():
                if self._stop_event.is_set():
                    break
                for slave_id, blocks in port_targets:
                    if self._stop_event.is_set():
                        break
                    for fc, start_reg, qty in blocks:
                        if self._stop_event.is_set():
                            break
                        last_end = self._last_tx_end.get(dev_path)
                        if last_end is not None:
                            remaining_silence = silence_sec - (time.monotonic() - last_end)
                            if remaining_silence > 0 and self._stop_event.wait(remaining_silence):
                                break
                        try:
                            req = build_modbus_rtu_read_request(slave_id, fc, start_reg, qty)
                            fd = self._ensure_fd_locked(dev_path)
                            try:
                                termios.tcflush(fd, termios.TCIFLUSH)
                            except (termios.error, OSError):
                                pass
                            _write_all_fd(fd, req, self.timeout_sec)
                            resp = read_modbus_rtu_response(
                                fd, slave_id, fc, qty, self.timeout_sec
                            )
                            self._last_tx_end[dev_path] = time.monotonic()
                        except (OSError, TimeoutError, ValueError, termios.error) as exc:
                            self._close_fd_locked(dev_path)
                            self._log_error_throttled(
                                f"Modbus RTU poll failed ({dev_path}, "
                                f"unit {slave_id} fc {fc} {start_reg}+{qty}): {exc}"
                            )
                            continue
                        self._enqueue_frame(req, resp)
                        polled += 1
        return polled

    def _run_loop(self):
        while not self._stop_event.is_set():
            self.poll_once()
            if self._stop_event.wait(self.interval_sec):
                break

    def start(self):
        """Start the background Modbus RTU polling thread (no-op if mode is 'off')."""
        if self.mode == "off" or self._thread is not None:
            return
        self.logger.info(
            f"Starting Modbus RTU poller ({self.mode} mode) every {self.interval_sec:.1f}s"
        )
        self._thread = threading.Thread(
            target=self._run_loop, name="modbus-rtu-poller", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0):
        """Signal the poller thread to stop, wait up to `timeout` seconds, and close all FDs."""
        self._stop_event.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout)
        with self._fd_lock:
            self._close_all_fds_locked()
