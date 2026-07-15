"""Tests for config_loader.ConfigLoader."""

from __future__ import annotations

from pathlib import Path

import pytest

from config_loader import ConfigLoader


def test_loads_nested_keys(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "api_key: test-key\n"
        "thresholds:\n"
        "  malicious: 51\n"
        "  suspicious: 11\n",
        encoding="utf-8",
    )

    config = ConfigLoader(str(config_file))

    assert config.get("api_key") == "test-key"
    assert config.get("thresholds.malicious") == 51
    assert config.get("thresholds.suspicious") == 11


def test_get_returns_default_for_missing_key(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("api_key: x\n", encoding="utf-8")

    config = ConfigLoader(str(config_file))

    assert config.get("missing") is None
    assert config.get("missing", "fallback") == "fallback"
    assert config.get("thresholds.malicious", 99) == 99


def test_require_returns_value(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("base_url: https://example.com\n", encoding="utf-8")

    config = ConfigLoader(str(config_file))

    assert config.require("base_url") == "https://example.com"


def test_require_raises_for_missing_key(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("api_key: present\n", encoding="utf-8")

    config = ConfigLoader(str(config_file))

    with pytest.raises(ValueError, match="base_url"):
        config.require("base_url")


def test_require_raises_for_empty_string(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text('api_key: ""\n', encoding="utf-8")

    config = ConfigLoader(str(config_file))

    with pytest.raises(ValueError, match="api_key"):
        config.require("api_key")


def test_missing_file_raises_friendly_error(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.yaml"

    with pytest.raises(FileNotFoundError, match="config.yaml not found"):
        ConfigLoader(str(missing))
