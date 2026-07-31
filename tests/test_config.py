"""Tests for config.py robustness: utf-8 encoding and version-derived UA fallback."""

import dataclasses
import os
import tempfile
from pathlib import Path

import pytest

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


# ---------------------------------------------------------------------------
# Config must not resolve against the *install* location
# ---------------------------------------------------------------------------

def test_cache_dir_is_not_inside_site_packages(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pip install put the cache in ``<venv>/Lib/.cache``.

    ``PROJECT_ROOT`` is derived from the package location, so for an installed
    package it is ``<venv>/Lib`` — and under ``uvx`` that environment is
    ephemeral, so the persistent cache was created and discarded on every run.
    The caching feature silently did nothing for the install path README
    recommends for the MCP server.
    """
    import pocmap.config as cfg

    fake_install = Path(tempfile.mkdtemp()) / "venv" / "Lib"
    fake_install.mkdir(parents=True)
    monkeypatch.setattr(cfg, "PROJECT_ROOT", fake_install)

    resolved = cfg._default_cache_dir()

    assert not str(resolved).startswith(str(fake_install)), (
        f"cache dir resolved inside the install tree: {resolved}"
    )


def test_cache_dir_stays_in_repo_for_a_source_checkout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Development stays self-contained — detected by pyproject.toml presence."""
    import pocmap.config as cfg

    checkout = Path(tempfile.mkdtemp())
    (checkout / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    monkeypatch.setattr(cfg, "PROJECT_ROOT", checkout)

    assert cfg._default_cache_dir() == checkout / ".cache"


def test_dotenv_is_discovered_from_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """README tells users to create a .env in their project; it must be read.

    It previously loaded only ``PROJECT_ROOT/.env`` = ``<venv>/Lib/.env`` for an
    installed package — a path no user ever writes to — so the documented .env
    workflow did nothing outside a source checkout.
    """
    import pocmap.config as cfg

    (tmp_path / ".env").write_text("POCMAP_THREAD_POOL_SIZE=7\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("POCMAP_THREAD_POOL_SIZE", raising=False)
    # Point the install root somewhere with no .env, so only CWD can supply it.
    monkeypatch.setattr(cfg, "PROJECT_ROOT", tmp_path / "nonexistent")

    assert cfg._build_settings().thread_pool_size == 7
