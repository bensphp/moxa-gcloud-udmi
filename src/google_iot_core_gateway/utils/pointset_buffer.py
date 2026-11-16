# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Bounded, disk-backed buffer for `events/pointset` messages during cloud outages."""

import collections
import json
import os
import tempfile
import threading
import time

OFFLINE_BUFFER_FILE_NAME = "offline_pointset_buffer.json"
DEFAULT_OFFLINE_BUFFER_MAX = 500
PERSIST_INTERVAL_SEC = 60.0


class PointsetBuffer:
    """Thread-safe bounded FIFO buffer of `(device_id, payload_json)` persisted to `state_dir`."""

    def __init__(
        self,
        logger,
        state_dir,
        max_messages: int = DEFAULT_OFFLINE_BUFFER_MAX,
        persist_interval_sec: float = PERSIST_INTERVAL_SEC,
    ):
        self.logger = logger
        self.state_dir = state_dir
        self.max_messages = int(max_messages)
        self.enabled = self.max_messages > 0
        self.persist_interval_sec = float(persist_interval_sec)
        self.path = os.path.join(state_dir, OFFLINE_BUFFER_FILE_NAME) if state_dir else None

        self._lock = threading.Lock()
        self._queue = collections.deque(maxlen=max(0, self.max_messages))
        self._dirty = False
        self._last_persist_mono = time.monotonic()
        self._dropped = 0
        self._last_drop_log = 0.0

        if self.enabled:
            self.load()

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)

    def load(self):
        """Restore any buffered messages left on disk from an earlier run."""
        if not self.enabled or not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            self.logger.warning(f"Ignoring unreadable offline buffer '{self.path}': {exc}")
            return
        items = data.get("messages") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return
        with self._lock:
            self._queue.clear()
            for item in items[-self.max_messages:]:
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("device_id"), str)
                    and isinstance(item.get("payload"), str)
                ):
                    self._queue.append((item["device_id"], item["payload"]))
            if self._queue:
                self.logger.info(
                    f"Loaded {len(self._queue)} offline pointset event(s) from '{self.path}'"
                )

    def append(self, device_id: str, payload: str, now_mono: float = None):
        """Queue a `events/pointset` payload, dropping the oldest entry when full."""
        if not self.enabled:
            return
        now = time.monotonic() if now_mono is None else now_mono
        with self._lock:
            if len(self._queue) >= self.max_messages:
                self._dropped += 1
                if now - self._last_drop_log >= 300.0:
                    self._last_drop_log = now
                    self.logger.warning(
                        f"Offline pointset buffer full ({self.max_messages}); "
                        f"dropped {self._dropped} oldest event(s)"
                    )
            self._queue.append((str(device_id), str(payload)))
            self._dirty = True
            self._maybe_persist_locked(force=False, now_mono=now)

    def prepend(self, device_id: str, payload: str):
        """Re-insert an event at the head of the queue after a failed drain publish."""
        if not self.enabled:
            return
        with self._lock:
            self._queue.appendleft((str(device_id), str(payload)))
            self._dirty = True

    def pop_batch(self, max_items: int = 10) -> list:
        """Pop up to `max_items` oldest `(device_id, payload)` tuples."""
        if not self.enabled or max_items <= 0:
            return []
        batch = []
        with self._lock:
            while self._queue and len(batch) < max_items:
                batch.append(self._queue.popleft())
            if batch:
                self._dirty = True
        return batch

    def maybe_persist(self, force: bool = False, now_mono: float = None) -> bool:
        """Persist queued messages to disk if dirty and either `force=True` or interval elapsed."""
        if not self.enabled:
            return False
        with self._lock:
            return self._maybe_persist_locked(force=force, now_mono=now_mono)

    def _maybe_persist_locked(self, force: bool = False, now_mono: float = None) -> bool:
        if not self._dirty or not self.path:
            return False
        now = time.monotonic() if now_mono is None else now_mono
        if not force and (now - self._last_persist_mono) < self.persist_interval_sec:
            return False
        if not self._queue:
            try:
                if os.path.exists(self.path):
                    os.remove(self.path)
            except OSError as exc:
                self.logger.warning(f"Could not remove empty offline buffer '{self.path}': {exc}")
                return False
            self._dirty = False
            self._last_persist_mono = now
            return True

        tmp_path = None
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix=".offline_buf_", dir=self.state_dir)
            payload = {
                "messages": [
                    {"device_id": dev_id, "payload": body}
                    for dev_id, body in self._queue
                ]
            }
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.path)
            tmp_path = None
            try:
                dir_fd = os.open(self.state_dir, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
            self._dirty = False
            self._last_persist_mono = now
            return True
        except OSError as exc:
            self.logger.warning(f"Could not write offline pointset buffer '{self.path}': {exc}")
            return False
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def close(self):
        """Flush any unsaved buffered events to disk on shutdown."""
        self.maybe_persist(force=True)
