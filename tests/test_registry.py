"""Native pytest tests for the generic :class:`PluginRegistry`.

Covers registration, lookup, listing, the defensive copy returned by ``all()``,
and — importantly — the duplicate-name guard branch, which no other test
currently exercises (so a regression removing it would go unnoticed).

Fully offline; no plugins are actually loaded from entry points.
"""

from __future__ import annotations

import pytest

from pocmap.utils.registry import PluginRegistry


def test_register_and_get_returns_plugin() -> None:
    reg: PluginRegistry[str] = PluginRegistry()
    ret = reg.register("alpha", "PLUGIN_A")
    assert ret == "PLUGIN_A"  # register returns the plugin (decorator-friendly)
    assert reg.get("alpha") == "PLUGIN_A"


def test_get_missing_returns_none() -> None:
    reg: PluginRegistry[str] = PluginRegistry()
    assert reg.get("missing") is None


def test_list_and_all_reflect_registrations() -> None:
    reg: PluginRegistry[str] = PluginRegistry()
    reg.register("alpha", "A")
    reg.register("beta", "B")
    assert reg.list() == ["alpha", "beta"]
    assert reg.all() == {"alpha": "A", "beta": "B"}


def test_all_returns_a_copy() -> None:
    reg: PluginRegistry[str] = PluginRegistry()
    reg.register("alpha", "A")
    snapshot = reg.all()
    snapshot["beta"] = "B"          # mutate the returned dict
    snapshot.pop("alpha")
    assert reg.all() == {"alpha": "A"}  # registry itself is unaffected
    assert reg.get("beta") is None


def test_reregistering_same_name_raises() -> None:
    reg: PluginRegistry[str] = PluginRegistry()
    reg.register("alpha", "A")
    with pytest.raises(ValueError, match="already registered"):
        reg.register("alpha", "A2")
