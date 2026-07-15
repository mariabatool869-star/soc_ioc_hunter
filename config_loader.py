"""Load YAML configuration for SOC IOC Hunter."""

from __future__ import annotations

import os
from typing import Any

import yaml


class ConfigLoader:
    """Read settings from a YAML file with dotted-key access."""

    def __init__(self, path: str = "config.yaml") -> None:
        if not os.path.exists(path):
            raise FileNotFoundError(
                "\n[FATAL] config.yaml not found!\n"
                "Copy config.example.yaml to config.yaml and add your API key.\n"
                "Required keys: api_key, base_url, retry_attempts, "
                "retry_delay, thresholds.\n"
            )
        with open(path, "r", encoding="utf-8") as handle:
            self.config: dict[str, Any] = yaml.safe_load(handle) or {}
            self.path = path

    def get(self, key_path: str, default: Any = None) -> Any:
        value: Any = self.config
        for key in key_path.split("."):
            if not isinstance(value, dict):
                return default
            if key not in value:
                return default
            value = value[key]
        return value

    def require(self, key_path: str) -> Any:
        value = self.get(key_path)
        if value is None or value == "":
            raise ValueError(f"[FATAL] '{key_path}' is missing from {self.path}")
        return value
