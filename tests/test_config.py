"""Tests for config.py robustness: utf-8 encoding and version-derived UA fallback."""

import dataclasses
import os
from pathlib import Path

from pocmap import __version__
from pocmap.config import _load_env_file, settings


def test_get_user_agent_reads_non_ascii(tmp_path: Path) -> None:
    ua_file = tmp_path / "user_agents.txt"
    ua_file.write_text("Mozilla/5.0 (é)\n", encoding="utf-8")
    s = dataclasses.replace(settings, user_agents_file=ua_file)
    ua = s._get_user_agent()
    assert isinstance(ua, str)
    assert ua


def test_get_user_agent_fallback_matches_version(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.txt"
    s = dataclasses.replace(settings, user_agents_file=missing)
    assert s._get_user_agent() == f"pocmap/{__version__}"


def test_load_env_file_non_ascii(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("# comment é\nPOCMAP_TEST_XYZ=value\n", encoding="utf-8")
    try:
        _load_env_file(env_path)
        assert os.environ.get("POCMAP_TEST_XYZ") == "value"
    finally:
        os.environ.pop("POCMAP_TEST_XYZ", None)
