"""Native offline pytest for NOTIFY (``latest``/``discover --notify <webhook>``).

The ``--notify`` flag POSTs a compact JSON summary of the notable CVEs to a
webhook. These tests lock in the security-critical and behavioural contract, all
fully offline (services mocked; the webhook sender either spied on or exercised
against the *real* SSRF guard, which rejects an internal target before any socket
is opened):

  * **Basic notify** — ``latest --notify <url>`` (mocked query) calls the guarded
    sender **exactly once** with a payload carrying the expected CVE ids/counts,
    exits ``0``, prints a domain-only confirmation, and never leaks the webhook
    URL path/token into stdout or stderr.
  * **Internal webhook rejected** — ``--notify http://169.254.169.254/`` is
    rejected by the *real* ``is_safe_url`` guard inside ``_post_webhook``: **no**
    POST is sent (the underlying ``HTTPClient.post_json`` is never reached), a
    clean (traceback-free) error is printed, and the command exits
    ``UPSTREAM_ERROR`` (5).
  * **--diff delta** — ``latest --diff --notify`` sends only the delta (added +
    KEV-gained / severity-escalated), never the unchanged or removed CVEs.
  * **Zero notable** — a result set with nothing critical/high/KEV **skips** the
    POST (documented behaviour) and prints a short note instead of pinging an
    empty summary.

The webhook URL used in the leak test embeds a distinctive ``SECRETTOKEN`` so the
assertion that it never appears in any output is meaningful. No network or DNS
call is ever made.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import pocmap.cli as cli_mod
import pocmap.services.snapshot as snapshot_mod
from pocmap.cli import app
from pocmap.config import settings
from pocmap.models import (
    CVEInfo,
    CVEState,
    CVSSScore,
    CVSSVersion,
    ExploitSource,
    RecentExploitResult,
    Severity,
)
from pocmap.services.recent_service import RecentService
from pocmap.utils.exit_codes import ExitCode
from pocmap.utils.http import HTTPClient

runner = CliRunner()

# A webhook whose path carries a secret token — the leak assertions key on it.
WEBHOOK = "https://hooks.example.test/services/T000/B000/SECRETTOKEN"
INTERNAL_WEBHOOK = "http://169.254.169.254/"


# ---------------------------------------------------------------------------
# Fixtures (deterministic in-memory model objects)
# ---------------------------------------------------------------------------


def _cve(
    cid: str,
    *,
    severity: Severity = Severity.CRITICAL,
    score: float = 9.8,
    epss: float = 50.0,
    kev: bool = False,
) -> CVEInfo:
    return CVEInfo(
        id=cid,
        description=f"{cid} test description",
        cvss=CVSSScore(
            version=CVSSVersion.V3_1,
            base_score=score,
            severity=severity,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        ),
        epss=epss,
        kev_status=kev,
        cwes=["CWE-502"],
        vendor="Apache",
        product="Log4j",
        publication_date="2021-12-10",
        state=CVEState.PUBLISHED,
    )


def _recent(cve: CVEInfo, *, has_poc: bool = False) -> RecentExploitResult:
    sources = [ExploitSource.GITHUB] if has_poc else []
    return RecentExploitResult(cve_info=cve, has_poc=has_poc, poc_sources=sources)


class _WebhookSpy:
    """Records every ``_post_webhook(url, payload)`` invocation."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, url: str, payload: dict[str, Any]) -> None:
        self.calls.append((url, payload))


class _PostJsonSpy:
    """Stand-in for ``HTTPClient.post_json`` that must never be reached."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args: Any, **kwargs: Any) -> SimpleNamespace:
        self.calls += 1
        return SimpleNamespace(status_code=200)


@pytest.fixture
def temp_snapshot_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the snapshot engine at an isolated temp cache dir (for --diff)."""
    monkeypatch.setattr(snapshot_mod, "settings", replace(settings, cache_dir=tmp_path))
    return tmp_path


def _patch_recent(monkeypatch: pytest.MonkeyPatch, results: list[RecentExploitResult]) -> None:
    monkeypatch.setattr(RecentService, "find_recent_cves", lambda self, **kw: list(results))


# ---------------------------------------------------------------------------
# Basic notify: guarded sender called once, exit 0, no token leak
# ---------------------------------------------------------------------------


def test_latest_notify_calls_sender_once_with_expected_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spy = _WebhookSpy()
    monkeypatch.setattr(cli_mod, "_post_webhook", spy)
    _patch_recent(
        monkeypatch,
        [
            _recent(_cve("CVE-2024-0001", severity=Severity.CRITICAL, kev=True)),
            _recent(_cve("CVE-2024-0002", severity=Severity.HIGH, kev=False)),
            # LOW + not-KEV: present in the result set but NOT notable.
            _recent(_cve("CVE-2024-0003", severity=Severity.LOW, score=2.1, kev=False)),
        ],
    )

    result = runner.invoke(app, ["latest", "--notify", WEBHOOK])

    assert result.exit_code == ExitCode.OK, result.stdout + result.stderr
    # The guarded sender was invoked exactly once...
    assert len(spy.calls) == 1
    sent_url, payload = spy.calls[0]
    assert sent_url == WEBHOOK
    # ...with a payload summarizing only the two notable CVEs.
    assert payload["count"] == 2
    ids = {item["id"] for item in payload["cves"]}
    assert ids == {"CVE-2024-0001", "CVE-2024-0002"}
    assert "CVE-2024-0003" not in ids
    # Each item carries the compact shape and a public NVD url (no token).
    first = payload["cves"][0]
    assert set(first) == {"id", "severity", "epss", "kev", "url"}
    assert first["url"].startswith("https://nvd.nist.gov/vuln/detail/")
    assert payload["kev_count"] == 1
    assert payload["source"] == "latest"
    assert "title" in payload


def test_latest_notify_confirmation_is_domain_only_no_token_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_mod, "_post_webhook", _WebhookSpy())
    _patch_recent(monkeypatch, [_recent(_cve("CVE-2024-0001", kev=True))])

    result = runner.invoke(app, ["latest", "--notify", WEBHOOK])

    assert result.exit_code == ExitCode.OK
    combined = result.stdout + result.stderr
    # The secret token / URL path never appears anywhere in the output...
    assert "SECRETTOKEN" not in combined
    assert "/services/" not in combined
    # ...but the confirmation names the target domain.
    assert "hooks.example.test" in result.stderr
    assert "Notified" in result.stderr


# ---------------------------------------------------------------------------
# Internal webhook: rejected by the real SSRF guard, no POST, exit 5
# ---------------------------------------------------------------------------


def test_latest_notify_internal_webhook_rejected_no_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # NOTE: _post_webhook is deliberately NOT mocked — the real SSRF guard runs.
    post_spy = _PostJsonSpy()
    monkeypatch.setattr(HTTPClient, "post_json", post_spy)
    _patch_recent(monkeypatch, [_recent(_cve("CVE-2024-0001", kev=True))])

    result = runner.invoke(app, ["latest", "--notify", INTERNAL_WEBHOOK])

    # The guard rejected the internal target BEFORE any POST was attempted.
    assert post_spy.calls == 0
    # Clean, categorized failure — not a masked success, not a traceback.
    assert result.exit_code == ExitCode.UPSTREAM_ERROR
    assert "Traceback" not in (result.stdout + result.stderr)
    assert "Notify failed" in result.stderr


# ---------------------------------------------------------------------------
# --diff: only the delta is sent
# ---------------------------------------------------------------------------


def test_latest_notify_with_diff_sends_only_delta(
    temp_snapshot_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Run 1 (no notify): establish the baseline snapshot.
    _patch_recent(
        monkeypatch,
        [
            _recent(_cve("CVE-2024-0001", kev=False)),
            _recent(_cve("CVE-2024-0002", kev=True)),
        ],
    )
    first = runner.invoke(app, ["latest", "--diff"])
    assert first.exit_code == ExitCode.OK, first.stdout + first.stderr

    # Run 2 (same query key -> same snapshot): CVE-0001 gains KEV, CVE-0003 is
    # new, CVE-0002 drops out. Only added + KEV-gained are notable.
    spy = _WebhookSpy()
    monkeypatch.setattr(cli_mod, "_post_webhook", spy)
    _patch_recent(
        monkeypatch,
        [
            _recent(_cve("CVE-2024-0001", kev=True)),  # KEV gained -> notable change
            _recent(_cve("CVE-2024-0003", kev=False)),  # added -> notable
        ],
    )
    second = runner.invoke(app, ["latest", "--diff", "--notify", WEBHOOK])

    assert second.exit_code == ExitCode.OK, second.stdout + second.stderr
    assert len(spy.calls) == 1
    _url, payload = spy.calls[0]
    ids = {item["id"] for item in payload["cves"]}
    assert ids == {"CVE-2024-0001", "CVE-2024-0003"}
    # The removed CVE is never notified.
    assert "CVE-2024-0002" not in ids
    assert payload["count"] == 2


# ---------------------------------------------------------------------------
# Zero notable -> POST is skipped (documented behaviour)
# ---------------------------------------------------------------------------


def test_latest_notify_zero_notable_skips_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spy = _WebhookSpy()
    monkeypatch.setattr(cli_mod, "_post_webhook", spy)
    # Only a LOW, non-KEV CVE -> nothing notable to push.
    _patch_recent(
        monkeypatch,
        [_recent(_cve("CVE-2024-0009", severity=Severity.LOW, score=2.1, kev=False))],
    )

    result = runner.invoke(app, ["latest", "--notify", WEBHOOK])

    assert result.exit_code == ExitCode.OK
    assert spy.calls == []  # no empty webhook ping
    assert "skipping" in result.stderr.lower()


def test_latest_notify_no_flag_never_calls_sender(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without --notify the sender is never touched (additive, no behaviour change)."""
    spy = _WebhookSpy()
    monkeypatch.setattr(cli_mod, "_post_webhook", spy)
    _patch_recent(monkeypatch, [_recent(_cve("CVE-2024-0001", kev=True))])

    result = runner.invoke(app, ["latest"])

    assert result.exit_code == ExitCode.OK
    assert spy.calls == []


# ---------------------------------------------------------------------------
# discover --notify: parity with latest
# ---------------------------------------------------------------------------


def test_discover_notify_calls_sender_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from pocmap.models import ProductDiscoveryResult, VersionConstraint
    from pocmap.services.product_service import ProductDiscoveryService

    discovery = ProductDiscoveryResult(
        query="Apache Log4j",
        normalized_vendor="apache",
        normalized_product="log4j",
        version_constraint=VersionConstraint(major=2, minor="x", raw="2.x", is_wildcard=True),
        total_found=2,
        confirmed_affected=[_cve("CVE-2021-44228", severity=Severity.CRITICAL, kev=True)],
        possibly_affected=[_cve("CVE-2021-45046", severity=Severity.HIGH, kev=False)],
        not_enough_data=[],
    )
    spy = _WebhookSpy()
    monkeypatch.setattr(cli_mod, "_post_webhook", spy)
    monkeypatch.setattr(
        ProductDiscoveryService, "discover_by_product", lambda self, **kw: discovery
    )

    result = runner.invoke(app, ["discover", "Apache Log4j", "--notify", WEBHOOK])

    assert result.exit_code == ExitCode.OK, result.stdout + result.stderr
    assert len(spy.calls) == 1
    _url, payload = spy.calls[0]
    assert payload["source"] == "discover"
    ids = {item["id"] for item in payload["cves"]}
    assert ids == {"CVE-2021-44228", "CVE-2021-45046"}
