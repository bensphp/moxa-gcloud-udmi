# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Small persistent key/value store used for data that must survive process restarts.

UDMI requires `state.system.operation.restart_count` to count real restarts, so the counter is
persisted on disk (pubber keeps the same counter in its persistent store).
"""

import json
import os
import tempfile

PERSISTENT_FILE_NAME = "persistent_data.json"


class PersistentStore:
    def __init__(self, logger, state_dir):
        self.logger = logger
        self.state_dir = state_dir
        self.path = os.path.join(state_dir, PERSISTENT_FILE_NAME) if state_dir else None

    def load(self) -> dict:
        if not self.path or not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError) as exc:
            self.logger.error(f"Ignoring unreadable persistent data '{self.path}': {exc}")
            return {}

    def save(self, data: dict) -> bool:
        if not self.path:
            return False
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix=".persistent_", dir=self.state_dir)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.path)
            return True
        except OSError as exc:
            self.logger.error(f"Could not write persistent data '{self.path}': {exc}")
            return False

    def increment_restart_count(self) -> int:
        """Increment and persist the process start counter; returns the new value (>= 1)."""
        data = self.load()
        try:
            count = int(data.get("restart_count") or 0) + 1
        except (TypeError, ValueError):
            count = 1
        data["restart_count"] = count
        if not self.save(data):
            self.logger.warning(
                "restart_count could not be persisted; it will not survive a restart "
                "(set environment_setup.state_dir to a writable directory)"
            )
        return count
