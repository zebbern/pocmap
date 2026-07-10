"""Native pytest tests for PLUGIN-SOURCES: third-party exploit sources.

A third-party package contributes an exploit source by declaring an
``importlib.metadata`` entry point in the ``pocmap.exploit_sources`` group. These
tests lock in the contract and its error isolation:

  * An injected in-process plugin's results appear in ``find_exploits`` and are
    labeled with the plugin's source name.
  * A plugin whose ``search`` raises degrades to a ``FetchStatus.ERROR`` source
    (never a crash, never a silent empty) while the built-in sources still
    return — including a plugin's *own programming bug* (a ``TypeError``), which,
    unlike our own code, is isolated rather than propagated.
  * A plugin returning a non-list, or non-``Exploit`` items, is skipped
    defensively without crashing.
  * With no plugins installed, behavior is byte-for-byte what it was before
    (regression guard).

Everything is fully offline: discovery is injected through the loader seam (or a
faked ``importlib.metadata.entry_points``), and the built-in GitHub/DB sources
are monkeypatched to return ``[]``, so no network is ever touched. No real entry
point is relied upon.
"""

from __future__ import annotations

import importlib.metadata
from typing import Any

import pytest

import pocmap.services.exploit_service as es_mod
from pocmap.models import Exploit, ExploitSource
from pocmap.services.exploit_service import (
    ExploitFindResult,
    ExploitService,
    LoadedPlugin,
    _coerce_exploits,
    _instantiate_plugin,
    _is_valid_plugin,
    _load_exploit_source_plugins,
    _plugin_label,
)
from pocmap.utils.http import FetchStatus

CVE = "CVE-2021-44228"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


def _plugin_exploits(n: int) -> list[Exploit]:
    """Build ``n`` fabricated third-party Exploit objects (ExploitSource.OTHER)."""
    return [
        Exploit(
            source=ExploitSource.OTHER,
            url=f"https://feed.example.invalid/pocs/{i}",
            title=f"Feed PoC {i}",
            language="Go",
        )
        for i in range(n)
    ]


class _StaticPlugin:
    """A well-behaved plugin returning a fixed list of exploits."""

    def __init__(self, exploits: list[Exploit], name: str = "acme-feed") -> None:
        self.name = name
        self._exploits = exploits

    def search(self, cve_id: str) -> list[Exploit]:
        return self._exploits


class _RaisingPlugin:
    """A plugin whose search raises the given exception (operational failure)."""

    name = "flaky-feed"

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def search(self, cve_id: str) -> list[Exploit]:
        raise self._exc


class _BadTypePlugin:
    """A plugin whose search returns something that is not ``list[Exploit]``."""

    name = "bad-feed"

    def __init__(self, value: Any) -> None:
        self._value = value

    def search(self, cve_id: str) -> Any:
        return self._value


class _FakeEntryPoint:
    """Minimal stand-in for ``importlib.metadata.EntryPoint``."""

    def __init__(self, name: str, target: Any, *, load_error: Exception | None = None) -> None:
        self.name = name
        self._target = target
        self._load_error = load_error

    def load(self) -> Any:
        if self._load_error is not None:
            raise self._load_error
        return self._target


def _make_service(
    monkeypatch: pytest.MonkeyPatch,
    plugins: list[LoadedPlugin],
    *,
    github: list[Exploit] | None = None,
    db: list[Exploit] | None = None,
) -> ExploitService:
    """Build an ExploitService with injected plugins and offline built-ins."""
    monkeypatch.setattr(es_mod, "_load_exploit_source_plugins", lambda: list(plugins))
    svc = ExploitService()
    monkeypatch.setattr(svc._github, "search_pocs", lambda cve_id: list(github or []))
    monkeypatch.setattr(svc._exploits, "search_all", lambda cve_id: list(db or []))
    return svc


# ---------------------------------------------------------------------------
# Happy path: plugin results are aggregated and labeled
# ---------------------------------------------------------------------------


def test_plugin_results_included_in_find_exploits(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _StaticPlugin(_plugin_exploits(3), name="acme-feed")
    svc = _make_service(monkeypatch, [LoadedPlugin("acme-feed", plugin)])

    exploits = svc.find_exploits(CVE)

    urls = {e.url for e in exploits}
    assert "https://feed.example.invalid/pocs/0" in urls
    assert len([e for e in exploits if e.source is ExploitSource.OTHER]) == 3


def test_plugin_source_labeled_in_status(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _StaticPlugin(_plugin_exploits(2), name="acme-feed")
    svc = _make_service(monkeypatch, [LoadedPlugin("acme-feed", plugin)])

    result = svc.find_exploits_with_status(CVE)
    assert isinstance(result, ExploitFindResult)
    statuses = {s.name: s for s in result.sources}
    # Built-ins still reported...
    assert statuses["github"].status is FetchStatus.EMPTY
    assert statuses["db"].status is FetchStatus.EMPTY
    # ...and the plugin is labeled + OK with the right count.
    assert statuses["acme-feed"].status is FetchStatus.OK
    assert statuses["acme-feed"].count == 2


def test_multiple_plugins_all_contribute(monkeypatch: pytest.MonkeyPatch) -> None:
    p1 = _StaticPlugin(_plugin_exploits(1), name="feed-a")
    p2 = _StaticPlugin(_plugin_exploits(2), name="feed-b")
    svc = _make_service(
        monkeypatch,
        [LoadedPlugin("feed-a", p1), LoadedPlugin("feed-b", p2)],
    )

    result = svc.find_exploits_with_status(CVE)
    names = {s.name for s in result.sources}
    assert {"github", "db", "feed-a", "feed-b"} <= names
    assert len(result.exploits) == 3


# ---------------------------------------------------------------------------
# Error isolation: a raising plugin degrades to ERROR, aggregate survives
# ---------------------------------------------------------------------------


def test_plugin_operational_error_degrades_to_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A network/HTTP failure in a plugin -> ERROR; built-ins still return."""
    from pocmap.utils.http import HTTPError

    plugin = _RaisingPlugin(HTTPError("feed down", status_code=503))
    db_hit = Exploit(source=ExploitSource.METASPLOIT, url="msf://x", title="mod")
    svc = _make_service(
        monkeypatch, [LoadedPlugin("flaky-feed", plugin)], db=[db_hit]
    )

    result = svc.find_exploits_with_status(CVE)
    statuses = {s.name: s.status for s in result.sources}
    assert statuses["flaky-feed"] is FetchStatus.ERROR
    assert statuses["db"] is FetchStatus.OK
    # The aggregate still returns the source that succeeded.
    assert [e.source for e in result.exploits] == [ExploitSource.METASPLOIT]


def test_plugin_rate_limit_reported_as_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plugin may signal throttling via RateLimitError -> RATE_LIMITED."""
    from pocmap.utils.http import RateLimitError

    plugin = _RaisingPlugin(RateLimitError("throttled", status_code=429))
    svc = _make_service(monkeypatch, [LoadedPlugin("flaky-feed", plugin)])

    result = svc.find_exploits_with_status(CVE)
    statuses = {s.name: s for s in result.sources}
    assert statuses["flaky-feed"].status is FetchStatus.RATE_LIMITED
    assert statuses["flaky-feed"].retryable is True


def test_plugin_programming_bug_is_isolated_not_propagated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plugin's OWN TypeError degrades to ERROR (third-party isolation).

    Contrast with our built-in sources, where a TypeError propagates (the
    FIX-GHPOC no-swallow guard, covered in tests/test_fetch_status.py). Plugins
    are untrusted third-party code, so their bug must not take the tool down.
    """
    plugin = _RaisingPlugin(TypeError("bug in third-party plugin"))
    db_hit = Exploit(source=ExploitSource.NUCLEI, url="nuclei://t", title="tmpl")
    svc = _make_service(
        monkeypatch, [LoadedPlugin("flaky-feed", plugin)], db=[db_hit]
    )

    # Must NOT raise, unlike a built-in programming bug.
    result = svc.find_exploits_with_status(CVE)
    statuses = {s.name: s.status for s in result.sources}
    assert statuses["flaky-feed"] is FetchStatus.ERROR
    assert statuses["db"] is FetchStatus.OK
    assert [e.source for e in result.exploits] == [ExploitSource.NUCLEI]

    # find_exploits (the plain-list API) likewise degrades without crashing.
    assert [e.source for e in svc.find_exploits(CVE)] == [ExploitSource.NUCLEI]


# ---------------------------------------------------------------------------
# Defensive coercion: bad return types are skipped, never crash
# ---------------------------------------------------------------------------


def test_plugin_non_list_return_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _BadTypePlugin({"not": "a list"})
    svc = _make_service(monkeypatch, [LoadedPlugin("bad-feed", plugin)])

    result = svc.find_exploits_with_status(CVE)
    statuses = {s.name: s.status for s in result.sources}
    # A non-list coerces to [] -> EMPTY (a successful-but-empty source), no crash.
    assert statuses["bad-feed"] is FetchStatus.EMPTY
    assert result.exploits == []


def test_plugin_non_exploit_items_are_filtered(monkeypatch: pytest.MonkeyPatch) -> None:
    good = _plugin_exploits(1)[0]
    plugin = _BadTypePlugin([good, "garbage", 42, {"nope": True}])
    svc = _make_service(monkeypatch, [LoadedPlugin("bad-feed", plugin)])

    result = svc.find_exploits_with_status(CVE)
    statuses = {s.name: s for s in result.sources}
    # Only the well-formed Exploit survives; the rest are dropped.
    assert statuses["bad-feed"].status is FetchStatus.OK
    assert statuses["bad-feed"].count == 1
    assert result.exploits == [good]


def test_coerce_exploits_unit() -> None:
    good = _plugin_exploits(2)
    assert _coerce_exploits(good, "x") == good
    assert _coerce_exploits("nope", "x") == []
    assert _coerce_exploits(None, "x") == []
    assert _coerce_exploits([good[0], "bad", 1], "x") == [good[0]]


# ---------------------------------------------------------------------------
# Regression guard: no plugins -> identical to pre-plugin behavior
# ---------------------------------------------------------------------------


def test_no_plugins_behavior_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """With zero plugins, only the two built-in sources are reported."""
    svc = _make_service(monkeypatch, [])
    assert svc._plugins == []

    result = svc.find_exploits_with_status(CVE)
    assert [s.name for s in result.sources] == ["github", "db"]
    assert svc.find_exploits(CVE) == []


def test_default_discovery_returns_list_and_no_example(monkeypatch: pytest.MonkeyPatch) -> None:
    """Real discovery (no injection) returns a list and never crashes.

    The bundled ``examples/example-exploit-source`` package is intentionally not
    installed, so it must not appear here.
    """
    loaded = _load_exploit_source_plugins()
    assert isinstance(loaded, list)
    assert "example" not in {lp.name for lp in loaded}


# ---------------------------------------------------------------------------
# Loader internals: entry-point discovery, instantiation, labeling, resilience
# ---------------------------------------------------------------------------


def test_entry_point_discovery_loads_class_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real loader path: a class entry point is loaded + instantiated."""

    class _EPClass:
        name = "from-ep"

        def search(self, cve_id: str) -> list[Exploit]:
            return _plugin_exploits(1)

    ep = _FakeEntryPoint("example", _EPClass)

    def _fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        assert group == es_mod.EXPLOIT_SOURCE_ENTRY_POINT_GROUP
        return [ep]

    monkeypatch.setattr(importlib.metadata, "entry_points", _fake_entry_points)

    loaded = _load_exploit_source_plugins()
    assert len(loaded) == 1
    assert loaded[0].name == "from-ep"
    assert loaded[0].plugin.search(CVE)[0].source is ExploitSource.OTHER


def test_broken_entry_point_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plugin that fails to load, and one missing search(), are both skipped."""

    class _NoSearch:
        pass

    good_ep = _FakeEntryPoint("good", _StaticPlugin(_plugin_exploits(1), name="good"))
    broken_ep = _FakeEntryPoint("broken", None, load_error=ImportError("boom"))
    invalid_ep = _FakeEntryPoint("invalid", _NoSearch)

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda *, group: [good_ep, broken_ep, invalid_ep],
    )

    loaded = _load_exploit_source_plugins()
    assert [lp.name for lp in loaded] == ["good"]


def test_discovery_never_crashes_on_enumeration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*, group: str) -> Any:
        raise RuntimeError("metadata backend exploded")

    monkeypatch.setattr(importlib.metadata, "entry_points", _boom)
    assert _load_exploit_source_plugins() == []


def test_plugin_label_resolution() -> None:
    class _WithSourceEnum:
        source = ExploitSource.OTHER

    class _WithNameStr:
        name = "  spaced-name  "

    class _WithNothing:
        pass

    assert _plugin_label(_WithSourceEnum(), "ep") == "other"
    assert _plugin_label(_WithNameStr(), "ep") == "spaced-name"
    assert _plugin_label(_WithNothing(), "ep-fallback") == "ep-fallback"


def test_instantiate_and_validate_helpers() -> None:
    class _Cls:
        def search(self, cve_id: str) -> list[Exploit]:
            return []

    # A class is instantiated; a ready instance is returned as-is.
    inst = _instantiate_plugin(_Cls)
    assert isinstance(inst, _Cls)
    ready = _Cls()
    assert _instantiate_plugin(ready) is ready

    assert _is_valid_plugin(_Cls()) is True
    assert _is_valid_plugin(object()) is False
