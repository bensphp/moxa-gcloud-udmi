# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Loader for Modbus-to-DBO JSON register maps in resources/modbus_dbo_maps."""

import json
from pathlib import Path


class ModbusToDBO:
    def __init__(self, logger, resources_path):
        self.logger = logger
        self.map = {}

        self._populate_the_map(resources_path)

    def _populate_the_map(self, resources_path):
        self.logger.debug("Populating the Modbus-To-DBO map")
        modbus_dbo_maps_path = Path(resources_path) / "modbus_dbo_maps"
        if not modbus_dbo_maps_path.is_dir():
            return

        for item in sorted(modbus_dbo_maps_path.iterdir()):
            if not (item.is_file() and item.suffix == ".json"):
                continue
            self.logger.info(f"Processing Modbus-To-DBO map: {item.name}")
            pm_type = item.stem
            with item.open("r", encoding="utf-8") as json_file:
                self.map[pm_type] = json.load(json_file)
        self.logger.debug("Populating the Modbus-To-DBO map completed!")
