"""
Automation Scripts for Bug Bounty CVE Assessment

Provides automation capabilities for:
- Bulk CVE assessment from scope files
- Continuous monitoring for new CVEs affecting scoped assets
- Automated report drafting from CVE data
- Webhook notifications for critical CVEs

Integration:
    - pocmap.services.cve_service for CVE lookups
    - pocmap.services.exploit_service for PoC retrieval
    - pocmap.bugbounty.scope_manager for scope matching
    - pocmap.bugbounty.prioritization for scoring
    - pocmap.bugbounty.templates for report generation

Example:
    from pocmap.bugbounty.automation import BulkCVEAssessor, ScopeMonitor

    # Bulk assessment
    assessor = BulkCVEAssessor()
    results = assessor.assess_from_scope("scope.json", strategy="composite")

    # Continuous monitoring
    monitor = ScopeMonitor(scope_manager)
    monitor.start_monitoring(interval_hours=24)
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pocmap.bugbounty.scope_manager import ScopeManager
from pocmap.utils.compat import get_value as _get_value
from pocmap.utils.http import HTTPClient, is_safe_url

# Shared, single-source path-traversal / null-byte guard.
# Re-exported as ``_safe_path`` because ``pocmap.cli`` imports this name from here.
from pocmap.utils.paths import safe_path as _safe_path

logger = logging.getLogger(__name__)


def _url_domain(url: str) -> str:
    """Extract host[:port] from URL for safe logging.

    Uses ``hostname`` (not ``netloc``) so any ``user:token@`` userinfo — a
    common place to smuggle a secret into a URL — is never echoed into a log
    line or exception message. Path/query/fragment are also excluded.
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        if not host:
            return "[invalid url]"
        return f"{parsed.scheme}://{host}" if parsed.scheme else host
    except Exception:
        return "[invalid url]"


def _post_webhook(webhook_url: str, payload: dict[str, Any]) -> None:
    """POST *payload* as JSON to *webhook_url* with full SSRF validation.

    Single choke point for every outbound webhook. Routes through
    :meth:`~pocmap.utils.http.HTTPClient.post_json`, which enforces both the
    static :func:`~pocmap.utils.http.is_safe_url` check *and* the
    :func:`~pocmap.utils.http.resolves_to_internal_ip` DNS check, and sends with
    redirect-following disabled (so a 3xx ``Location`` cannot bounce the POST to
    an internal host such as cloud metadata or localhost).

    Raises ``ValueError`` on a statically-unsafe URL and ``HTTPError`` on an
    internal-resolving target or transport failure. Callers log domain-only via
    :func:`_url_domain`; neither this helper nor ``post_json`` ever places the
    full URL (which may carry a webhook token) in an exception message.
    """
    if not is_safe_url(webhook_url):
        raise ValueError(f"Unsafe webhook URL: {_url_domain(webhook_url)}")
    with HTTPClient(timeout=30) as client:
        client.post_json(webhook_url, payload)


# Field-name mappings between raw dicts and CVEInfo Pydantic models.
_CVE_ATTR_MAP = {
    "cve_id": "id",
    "cvss_score": "cvss",
    "epss_score": "epss",
    "kev_listed": "kev_status",
    "kev": "kev_status",
    "affected_product": "product",
}


def _get_cve_value(obj: Any, key: str, default: Any = None) -> Any:
    """Get a value from a CVE dict or Pydantic model.

    Handles field-name mappings between raw dicts (e.g. ``cve_id``,
    ``cvss_score``) and :class:`~pocmap.models.CVEInfo` Pydantic
    models (e.g. ``id``, ``cvss``).

    For the ``cvss`` / ``cvss_score`` keys, nested
    :class:`~pocmap.models.CVSSScore` models are automatically
    unwrapped to return the scalar ``base_score``.
    """
    if obj is None:
        return default

    # Resolve key name for Pydantic models (e.g. cve_id -> id)
    attr_name = _CVE_ATTR_MAP.get(key, key)

    # Use shared helper for the underlying access
    val = _get_value(obj, attr_name, default)
    if val is None or (callable(val) and attr_name != key):
        return default

    # Unwrap nested CVSSScore -> base_score when the caller
    # asked for a scalar cvss/cvss_score value.
    if attr_name == "cvss" and key in ("cvss", "cvss_score"):
        if val is not None and hasattr(val, "base_score"):
            return val.base_score
        return val if val is not None else default

    return val if val is not None else default


# ═══════════════════════════════════════════════════════════════════════════════
# BULK CVE ASSESSOR
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AssessmentResult:
    """Result of a single CVE assessment."""
    cve_id: str
    in_scope: bool
    priority_score: float
    cvss_score: float
    epss_score: float
    has_exploit: bool
    is_kev: bool
    bounty_estimate_low: int
    bounty_estimate_high: int
    affected_assets: list[str] = field(default_factory=list)
    recommended_action: str = ""
    assessed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "in_scope": self.in_scope,
            "priority_score": self.priority_score,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "has_exploit": self.has_exploit,
            "is_kev": self.is_kev,
            "bounty_estimate_low": self.bounty_estimate_low,
            "bounty_estimate_high": self.bounty_estimate_high,
            "affected_assets": self.affected_assets,
            "recommended_action": self.recommended_action,
            "assessed_at": self.assessed_at,
        }


class BulkCVEAssessor:
    """
    Bulk assess CVEs against a scope file and prioritize findings.

    Takes a scope definition and list of CVEs, then scores and
    prioritizes them for bug bounty action.

    Example:
        assessor = BulkCVEAssessor()
        results = assessor.assess_from_scope(
            scope_file="scope.json",
            cve_list=[{"id": "CVE-2021-44228", ...}],
            strategy="composite",
        )
        assessor.export_results("assessment.json")
    """

    def __init__(self) -> None:
        self.results: list[AssessmentResult] = []
        self.assessed_at = ""

    def assess_from_scope(
        self,
        scope_file: str,
        cve_list: list[dict[str, Any]],
        strategy: str = "composite",
        min_cvss: float = 4.0,
        require_exploit: bool = False,
        limit: int = 50,
    ) -> list[AssessmentResult]:
        """
        Assess a list of CVEs against a scope file.

        Args:
            scope_file: Path to scope JSON file
            cve_list: List of CVE dictionaries
            strategy: Prioritization strategy
            min_cvss: Minimum CVSS score to include
            require_exploit: Only include CVEs with exploits
            limit: Maximum results

        Returns:
            List of AssessmentResult objects
        """
        from pocmap.bugbounty.prioritization import (
            calculate_bounty_potential,
            prioritize_cves,
        )
        from pocmap.bugbounty.scope_manager import ScopeManager

        self.assessed_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"

        # Load scope (with path traversal validation)
        safe_scope_file = _safe_path(scope_file)
        scope_manager = ScopeManager()
        scope_manager.load_scope_file(safe_scope_file)

        # Match CVEs to scope
        matched_cves = scope_manager.match_cves_to_scope(cve_list)

        # Prioritize
        prioritized = prioritize_cves(
            matched_cves,
            strategy=strategy,
            min_cvss=min_cvss,
            require_exploit=require_exploit,
            limit=limit,
        )

        # Build results
        self.results = []
        for cve in prioritized:
            bounty = calculate_bounty_potential(cve)

            result = AssessmentResult(
                cve_id=_get_cve_value(cve, "id") or _get_cve_value(cve, "cve_id", "Unknown"),
                in_scope=_get_cve_value(cve, "in_scope", True),
                priority_score=_get_cve_value(cve, "priority_score", 0),
                cvss_score=_get_cve_value(cve, "cvss") or _get_cve_value(cve, "cvss_score", 0),
                epss_score=_get_cve_value(cve, "epss") or _get_cve_value(cve, "epss_score", 0),
                has_exploit=_get_cve_value(cve, "exploit_available", False),
                is_kev=_get_cve_value(cve, "kev_listed", False),
                bounty_estimate_low=bounty["estimated_low"],
                bounty_estimate_high=bounty["estimated_high"],
                affected_assets=_get_cve_value(cve, "matched_assets", []),
                recommended_action=bounty["recommendation"],
                assessed_at=self.assessed_at,
            )
            self.results.append(result)

        return self.results

    def assess_from_cve_file(
        self,
        scope_file: str,
        cve_file: str,
        strategy: str = "composite",
        min_cvss: float = 4.0,
    ) -> list[AssessmentResult]:
        """
        Assess CVEs from a JSON file against scope.

        Args:
            scope_file: Path to scope file
            cve_file: Path to JSON file containing CVE list
            strategy: Prioritization strategy
            min_cvss: Minimum CVSS score

        Returns:
            List of AssessmentResult objects
        """
        safe_cve_file = _safe_path(cve_file)
        with open(safe_cve_file) as f:
            cve_list = json.load(f)
        return self.assess_from_scope(
            scope_file, cve_list, strategy, min_cvss
        )

    def get_quick_wins(self, min_score: float = 60) -> list[AssessmentResult]:
        """
        Get 'quick win' CVEs - high score with available exploits.

        Args:
            min_score: Minimum priority score

        Returns:
            List of quick-win opportunities
        """
        return [
            r for r in self.results
            if r.priority_score >= min_score and r.has_exploit
        ]

    def get_high_value_targets(self, min_bounty: int = 1000) -> list[AssessmentResult]:
        """
        Get high-value targets by estimated bounty.

        Args:
            min_bounty: Minimum estimated bounty

        Returns:
            List of high-value opportunities
        """
        return [
            r for r in self.results
            if r.bounty_estimate_high >= min_bounty
        ]

    def get_kev_targets(self) -> list[AssessmentResult]:
        """Get all KEV-listed CVEs in scope."""
        return [r for r in self.results if r.is_kev]

    def export_results(self, filepath: str, format: str = "json") -> None:
        """
        Export assessment results to file.

        Args:
            filepath: Output file path
            format: Output format (json, csv, markdown)
        """
        if format == "json":
            data = {
                "assessed_at": self.assessed_at,
                "total_cves": len(self.results),
                "in_scope": len([r for r in self.results if r.in_scope]),
                "with_exploits": len([r for r in self.results if r.has_exploit]),
                "kev_count": len([r for r in self.results if r.is_kev]),
                "estimated_total_bounty_low": sum(r.bounty_estimate_low for r in self.results),
                "estimated_total_bounty_high": sum(r.bounty_estimate_high for r in self.results),
                "results": [r.to_dict() for r in self.results],
            }
            safe_filepath = _safe_path(filepath)
            with open(safe_filepath, "w") as f:
                json.dump(data, f, indent=2)

        elif format == "markdown":
            lines = [
                "# CVE Assessment Results",
                "",
                f"**Assessed:** {self.assessed_at}",
                f"**Total CVEs:** {len(self.results)}",
                f"**With Exploits:** {len([r for r in self.results if r.has_exploit])}",
                f"**KEV Listed:** {len([r for r in self.results if r.is_kev])}",
                "",
                "| Rank | CVE | CVSS | EPSS | KEV | Exploit | Score | Bounty Est. | Action |",
                "|------|-----|------|------|-----|---------|-------|-------------|--------|",
            ]
            for i, r in enumerate(self.results, 1):
                bounty = f"${r.bounty_estimate_low}-${r.bounty_estimate_high}"
                lines.append(
                    f"| {i} | {r.cve_id} | {r.cvss_score} | {r.epss_score} | "
                    f"{'Yes' if r.is_kev else 'No'} | {'Yes' if r.has_exploit else 'No'} | "
                    f"{r.priority_score:.1f} | {bounty} | {r.recommended_action[:40]}... |"
                )
            safe_filepath = _safe_path(filepath)
            with open(safe_filepath, "w") as f:
                f.write("\n".join(lines))

        elif format == "csv":
            import csv
            safe_filepath = _safe_path(filepath)
            with open(safe_filepath, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "rank", "cve_id", "cvss", "epss", "kev",
                    "has_exploit", "priority_score",
                    "bounty_low", "bounty_high", "recommended_action",
                ])
                for i, r in enumerate(self.results, 1):
                    writer.writerow([
                        i, r.cve_id, r.cvss_score, r.epss_score,
                        "Yes" if r.is_kev else "No",
                        "Yes" if r.has_exploit else "No",
                        r.priority_score,
                        r.bounty_estimate_low, r.bounty_estimate_high,
                        r.recommended_action,
                    ])

    def print_summary(self) -> None:
        """Print a human-readable summary to stdout."""
        if not self.results:
            print("No assessment results available.")
            return

        print("=" * 70)
        print("CVE ASSESSMENT SUMMARY")
        print("=" * 70)
        print(f"Assessed at: {self.assessed_at}")
        print(f"Total CVEs analyzed: {len(self.results)}")
        print(f"  - In scope: {len([r for r in self.results if r.in_scope])}")
        print(f"  - With exploits: {len([r for r in self.results if r.has_exploit])}")
        print(f"  - KEV listed: {len([r for r in self.results if r.is_kev])}")
        print()

        total_low = sum(r.bounty_estimate_low for r in self.results)
        total_high = sum(r.bounty_estimate_high for r in self.results)
        print(f"Estimated total bounty range: ${total_low} - ${total_high}")
        print()

        print("TOP 10 PRIORITIES:")
        print("-" * 70)
        for i, r in enumerate(self.results[:10], 1):
            badge = ""
            if r.is_kev:
                badge = " [KEV]"
            elif r.has_exploit:
                badge = " [EXPLOIT]"
            print(f"  {i}. {r.cve_id} - Score: {r.priority_score:.1f}{badge}")
            print(f"     CVSS: {r.cvss_score} | EPSS: {r.epss_score}")
            print(f"     Bounty: ${r.bounty_estimate_low}-${r.bounty_estimate_high}")
            print(f"     Action: {r.recommended_action[:70]}")
            print()

        print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════════
# CONTINUOUS MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

class ScopeMonitor:
    """
    Continuously monitor for new CVEs affecting scoped assets.

    Polls CVE sources at regular intervals and alerts when new,
high-impact CVEs are discovered that match the scope.

    Example:
        monitor = ScopeMonitor(scope_manager)
        monitor.add_alert_webhook("https://hooks.slack.com/...")
        monitor.start_monitoring(interval_hours=24)
    """

    def __init__(self, scope_manager: ScopeManager | None = None) -> None:
        self.scope_manager = scope_manager or ScopeManager()
        self.known_cves: set[str] = set()
        self.webhooks: list[str] = []
        self.alert_threshold: float = 7.0  # Minimum CVSS to alert
        self.is_running: bool = False
        self.last_check: str | None = None
        self.history: list[dict[str, Any]] = []

    def add_alert_webhook(self, webhook_url: str) -> None:
        """Add a webhook URL for alerts."""
        self.webhooks.append(webhook_url)

    def set_alert_threshold(self, min_cvss: float) -> None:
        """Set minimum CVSS score for alerts."""
        self.alert_threshold = min_cvss

    def load_known_cves(self, filepath: str) -> None:
        """Load previously known CVEs to avoid duplicate alerts."""
        safe_filepath = _safe_path(filepath)
        path = Path(safe_filepath)
        if path.exists():
            with open(safe_filepath) as f:
                data = json.load(f)
                self.known_cves = set(data.get("known_cves", []))

    def save_known_cves(self, filepath: str) -> None:
        """Save known CVEs to file."""
        safe_filepath = _safe_path(filepath)
        with open(safe_filepath, "w") as f:
            json.dump({
                "known_cves": sorted(self.known_cves),
                "saved_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            }, f, indent=2)

    def check_new_cves(self, cve_source: Callable[..., Any] | None = None) -> list[dict[str, Any]]:
        """
        Check for new CVEs and return matches against scope.

        Args:
            cve_source: Optional function to fetch CVEs.
                       Defaults to checking recent CVE feeds.

        Returns:
            List of new matching CVEs
        """
        self.last_check = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"

        # Fetch new CVEs
        new_cves = cve_source() if cve_source else self._fetch_recent_cves()

        # Filter to new (unknown) CVEs
        truly_new = [c for c in new_cves if _get_cve_value(c, "id") not in self.known_cves]

        if not truly_new:
            return []

        # Match to scope
        matched = self.scope_manager.match_cves_to_scope(truly_new)

        # Filter by threshold
        alerts = []
        for cve in matched:
            cvss = _get_cve_value(cve, "cvss") or _get_cve_value(cve, "cvss_score", 0)
            if isinstance(cvss, (int, float)) and cvss >= self.alert_threshold:
                alerts.append(cve)

        # Update known set
        for cve in truly_new:
            self.known_cves.add(_get_cve_value(cve, "id"))

        # Record in history
        self.history.append({
            "timestamp": self.last_check,
            "checked_count": len(new_cves),
            "new_count": len(truly_new),
            "matched_count": len(matched),
            "alert_count": len(alerts),
            "alerted_cves": [_get_cve_value(c, "id") for c in alerts],
        })

        # Send notifications
        if alerts:
            self._send_alerts(alerts)

        return alerts

    def _fetch_recent_cves(self) -> list[dict[str, Any]]:
        """
        Fetch recent CVEs from available sources.

        This is a placeholder that returns an empty list.
        In production, integrate with:
        - NVD API (nvd_client.get_recent())
        - CISA KEV feed
        - pocmap.clients.cveorg_client for CVE.org data
        """
        # Placeholder - should be implemented with actual CVE source
        return []

    def _send_alerts(self, cves: list[dict[str, Any]]) -> None:
        """Send alert notifications via configured webhooks."""
        if not self.webhooks:
            return

        message = self._format_alert_message(cves)

        for webhook_url in self.webhooks:
            try:
                if "slack" in webhook_url:
                    self._send_slack(webhook_url, message)
                elif "discord" in webhook_url:
                    self._send_discord(webhook_url, message)
                else:
                    self._send_generic_webhook(webhook_url, message)
            except Exception as e:
                logger.error("Failed to send alert to %s: %s", _url_domain(webhook_url), e)

    def _format_alert_message(self, cves: list[dict[str, Any]]) -> dict[str, Any]:
        """Format alert message for webhooks."""
        cve_list = "\n".join([
            f"- {_get_cve_value(c, 'id', 'Unknown')} "
            f"(CVSS: {_get_cve_value(c, 'cvss', 'N/A')}) - "
            f"{_get_cve_value(c, 'title') or _get_cve_value(c, 'description', '')[:60]}"
            for c in cves[:10]
        ])

        return {
            "text": f"*CVE Alert: {len(cves)} new matching CVEs detected*",
            "details": cve_list,
            "count": len(cves),
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "cves": cves,
        }

    def _send_slack(self, webhook_url: str, message: dict[str, Any]) -> None:
        """Send Slack webhook notification."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"CVE Alert: {message['count']} new matching CVEs",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message["details"]},
            },
        ]
        _post_webhook(webhook_url, {"blocks": blocks})

    def _send_discord(self, webhook_url: str, message: dict[str, Any]) -> None:
        """Send Discord webhook notification."""
        cves = message.get("cves", [])
        fields = []
        for cve in cves[:10]:
            fields.append({
                "name": _get_cve_value(cve, "id", "Unknown"),
                "value": f"CVSS: {_get_cve_value(cve, 'cvss', 'N/A')} | {_get_cve_value(cve, 'title') or _get_cve_value(cve, 'description', '')[:80]}",
                "inline": False,
            })

        _post_webhook(webhook_url, {
            "embeds": [{
                "title": f"CVE Alert: {message['count']} new matching CVEs",
                "description": "New CVEs matching your bug bounty scope have been detected.",
                "color": 15158332,  # Orange
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                "footer": {"text": "PocMap Bug Bounty Monitor"},
            }],
        })

    def _send_generic_webhook(self, webhook_url: str, message: dict[str, Any]) -> None:
        """Send generic webhook notification."""
        _post_webhook(webhook_url, message)

    def start_monitoring(
        self, interval_hours: int = 24, callback: Callable[..., Any] | None = None
    ) -> None:
        """
        Start continuous monitoring loop.

        Args:
            interval_hours: Hours between checks
            callback: Optional callback function for new CVEs
        """
        self.is_running = True
        interval_seconds = interval_hours * 3600

        print(f"Starting CVE monitoring (interval: {interval_hours}h)")
        print(f"Alert threshold: CVSS >= {self.alert_threshold}")
        print(f"Webhooks configured: {len(self.webhooks)}")

        while self.is_running:
            try:
                new_cves = self.check_new_cves()
                if new_cves:
                    print(f"ALERT: {len(new_cves)} new matching CVEs detected!")
                    for cve in new_cves:
                        cve_id = _get_cve_value(cve, "id", "Unknown")
                        title = _get_cve_value(cve, "title") or _get_cve_value(cve, "description", "")[:60]
                        print(f"  - {cve_id}: {title}")
                    if callback:
                        callback(new_cves)
                else:
                    print(f"[{datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}] No new matching CVEs.")
            except Exception as e:
                print(f"Monitoring error: {e}")

            # Sleep with interrupt check
            for _ in range(interval_seconds):
                if not self.is_running:
                    break
                time.sleep(1)

    def stop_monitoring(self) -> None:
        """Stop the monitoring loop."""
        self.is_running = False
        print("Monitoring stopped.")


# ═══════════════════════════════════════════════════════════════════════════════
# AUTOMATED REPORT DRAFTER
# ═══════════════════════════════════════════════════════════════════════════════

class ReportDrafter:
    """
    Automated report drafting from CVE data.

    Takes CVE information and automatically generates platform-specific
    bug bounty reports with proper formatting and structure.

    Example:
        drafter = ReportDrafter()
        report = drafter.draft_report(
            cve_data=cve_info,
            platform="hackerone",
            impact="Remote code execution achieved",
            steps="1. Send crafted request to /api/v1/upload...",
        )
        drafter.save_report("report.md")
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.last_report: str = ""
        self.report_history: list[dict[str, Any]] = []

    def draft_report(
        self,
        cve_data: dict[str, Any],
        platform: str = "hackerone",
        impact: str = "",
        steps: str = "",
        title: str = "",
        poc_code: str = "",
        **kwargs: Any,
    ) -> str:
        """
        Draft a bug bounty report from CVE data.

        Args:
            cve_data: CVE information dictionary
            platform: Target platform (hackerone, bugcrowd, intigriti)
            impact: Impact description
            steps: Reproduction steps
            title: Custom title (auto-generated if empty)
            poc_code: Proof-of-concept code
            **kwargs: Additional template variables

        Returns:
            Rendered report string
        """
        from pocmap.bugbounty.templates import (
            TemplateConfig,
            get_template,
        )

        # Build template config
        template_config = TemplateConfig(
            researcher_name=self.config.get("researcher_name", ""),
            researcher_handle=self.config.get("researcher_handle", ""),
            program_name=self.config.get("program_name", ""),
            target_url=self.config.get("target_url", ""),
            platform=platform,
        )

        # Get template
        template = get_template(platform, config=template_config)

        # Build context (handles both dict and Pydantic model via ** unpacking)
        # Convert Pydantic model to plain dict first so ** unpacking works
        cve_dict = cve_data
        if hasattr(cve_data, "model_dump"):
            cve_dict = cve_data.model_dump(mode="json")
        elif not isinstance(cve_data, dict):
            cve_dict = dict(cve_data)

        context = {
            **cve_dict,
            "impact_description": impact,
            "reproduction_steps": steps,
            "poc_code": poc_code,
            **kwargs,
        }

        # Ensure cve_id key exists for both dicts (field ``cve_id``) and models (field ``id``)
        if "cve_id" not in context:
            context["cve_id"] = _get_cve_value(cve_data, "cve_id", "N/A")

        if title:
            context["title"] = title
        elif "title" not in context:
            cve_id = _get_cve_value(cve_data, "id") or _get_cve_value(cve_data, "cve_id", "Unknown")
            product = _get_cve_value(cve_data, "affected_product", "Target")
            context["title"] = f"Vulnerability in {product} ({cve_id})"

        # Set defaults for missing fields
        context.setdefault("executive_summary", f"A vulnerability ({context.get('cve_id', 'N/A')}) was identified that could allow {impact[:100] if impact else 'unauthorized access'}.")
        context.setdefault("vulnerability_description", _get_cve_value(cve_data, "description", ""))
        context.setdefault("root_cause", _get_cve_value(cve_data, "root_cause", "Insufficient input validation"))
        context.setdefault("attack_vector", _get_cve_value(cve_data, "attack_vector", "Network"))
        cve_product = _get_cve_value(cve_data, "affected_product", "the affected product")
        fixed_ver = _get_cve_value(cve_data, "fixed_version", "the latest version")
        context.setdefault("remediation_primary", f"Upgrade {cve_product} to version {fixed_ver}.")
        context.setdefault("temporary_mitigations", "Implement WAF rules to filter malicious requests until patching is complete.")
        context.setdefault("references", _get_cve_value(cve_data, "references", f"- https://nvd.nist.gov/vuln/detail/{_get_cve_value(cve_data, 'cve_id', '')}"))

        # Render
        report = template.render(**context)
        self.last_report = report
        self.report_history.append({
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "platform": platform,
            "cve_id": _get_cve_value(cve_data, "id") or _get_cve_value(cve_data, "cve_id", ""),
        })

        return report

    def draft_multi_cve_report(
        self,
        cves: list[dict[str, Any]],
        platform: str = "internal",
        title: str = "Security Assessment Report",
        **kwargs: Any,
    ) -> str:
        """
        Draft a report covering multiple CVEs.

        Args:
            cves: List of CVE dictionaries
            platform: Target platform
            title: Report title
            **kwargs: Additional context

        Returns:
            Rendered report string
        """
        from pocmap.bugbounty.templates import (
            InternalAssessmentTemplate,
            TemplateConfig,
        )

        config = TemplateConfig(
            researcher_name=self.config.get("researcher_name", ""),
            program_name=self.config.get("program_name", ""),
            target_url=self.config.get("target_url", ""),
        )

        template = InternalAssessmentTemplate(config=config)
        report = template.render_multi_cve(cves, title=title, **kwargs)
        self.last_report = report

        return report

    def save_report(self, filepath: str) -> None:
        """Save the last generated report to file."""
        if not self.last_report:
            raise ValueError("No report to save. Generate a report first.")
        safe_filepath = _safe_path(filepath)
        with open(safe_filepath, "w") as f:
            f.write(self.last_report)

    def generate_poc_template(self, vuln_type: str, language: str = "python") -> str:
        """
        Generate a PoC code template for a vulnerability type.

        Args:
            vuln_type: Type of vulnerability (rce, sqli, xss, ssrf, etc.)
            language: Programming language (python, bash, ruby)

        Returns:
            PoC code template
        """
        templates = {
            "rce": {
                "python": '''#!/usr/bin/env python3
"""
PoC for RCE via {cve_id}
Target: {target_url}
"""
import requests
import sys

TARGET = "{target_url}"
PAYLOAD = "{payload}"

def exploit(target_url: str) -> bool:
    """Execute RCE PoC."""
    url = f"{target_url}/vulnerable-endpoint"
    headers = {"Content-Type": "application/json"}
    data = {{"input": PAYLOAD}}

    try:
        resp = requests.post(url, json=data, headers=headers, timeout=30)
        if "proof-of-execution" in resp.text:
            print(f"[+] RCE confirmed on {{target_url}}")
            return True
    except Exception as e:
        print(f"[-] Error: {{e}}")

    return False

if __name__ == "__main__":
    if exploit(TARGET):
        sys.exit(0)
    sys.exit(1)
''',
            },
            "sqli": {
                "python": '''#!/usr/bin/env python3
"""
PoC for SQL Injection via {cve_id}
"""
import requests

TARGET = "{target_url}"
PAYLOAD = "{payload}"

def test_sqli(target: str) -> bool:
    """Test for SQL injection."""
    url = f"{{target}}/search"
    params = {{"q": PAYLOAD}}

    resp = requests.get(url, params=params, timeout=30)

    # Time-based detection
    if resp.elapsed.total_seconds() > 5:
        print(f"[+] Time-based SQLi confirmed")
        return True

    # Error-based detection
    if any(err in resp.text for err in ["SQL syntax", "mysql_fetch", "ORA-"]):
        print(f"[+] Error-based SQLi confirmed")
        return True

    return False

if __name__ == "__main__":
    test_sqli(TARGET)
''',
            },
            "ssrf": {
                "python": '''#!/usr/bin/env python3
"""
PoC for SSRF via {cve_id}
"""
import requests

TARGET = "{target_url}"
PAYLOAD = "http://169.254.169.254/latest/meta-data/"  # AWS metadata

def test_ssrf(target: str) -> bool:
    """Test for SSRF."""
    url = f"{{target}}/fetch"
    data = {{"url": PAYLOAD}}

    resp = requests.post(url, json=data, timeout=30)

    if "ami-id" in resp.text or "instance-id" in resp.text:
        print(f"[+] SSRF to cloud metadata confirmed")
        return True

    return False

if __name__ == "__main__":
    test_ssrf(TARGET)
''',
            },
        }

        vuln_lower = vuln_type.lower()
        if vuln_lower not in templates:
            vuln_lower = "rce"  # Default

        lang_templates = templates.get(vuln_lower, templates["rce"])
        return lang_templates.get(language, lang_templates["python"])


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class NotificationManager:
    """
    Manages notifications for critical CVE discoveries.

    Supports multiple notification channels:
    - Slack webhooks
    - Discord webhooks
    - Generic webhooks
    - File-based logging
    - Desktop notifications

    Example:
        notifier = NotificationManager()
        notifier.add_slack_webhook("https://hooks.slack.com/...")
        notifier.add_discord_webhook("https://discord.com/api/webhooks/...")
        notifier.notify_critical_cve(cve_data)
    """

    def __init__(self) -> None:
        self.webhooks: dict[str, list[str]] = {
            "slack": [],
            "discord": [],
            "generic": [],
        }
        self.log_file: str | None = None
        self.desktop_enabled: bool = False

    def add_slack_webhook(self, url: str) -> None:
        """Add a Slack webhook URL."""
        self.webhooks["slack"].append(url)

    def add_discord_webhook(self, url: str) -> None:
        """Add a Discord webhook URL."""
        self.webhooks["discord"].append(url)

    def add_generic_webhook(self, url: str) -> None:
        """Add a generic webhook URL."""
        self.webhooks["generic"].append(url)

    def set_log_file(self, filepath: str) -> None:
        """Set a log file for notifications."""
        self.log_file = _safe_path(filepath)

    def notify_critical_cve(self, cve_data: dict[str, Any], message: str = "") -> None:
        """
        Send notification about a critical CVE.

        Args:
            cve_data: CVE information dictionary or CVEInfo model
            message: Optional custom message
        """
        cve_id = _get_cve_value(cve_data, "id") or _get_cve_value(cve_data, "cve_id", "Unknown")
        cvss = _get_cve_value(cve_data, "cvss") or _get_cve_value(cve_data, "cvss_score", "N/A")
        title = _get_cve_value(cve_data, "title") or _get_cve_value(cve_data, "description", "No title")

        if not message:
            message = (
                f"CRITICAL CVE Alert: {cve_id}\\n"
                f"CVSS: {cvss} | {title[:100]}\\n"
                f"Immediate action recommended."
            )

        notification = {
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "level": "CRITICAL",
            "cve_id": cve_id,
            "cvss": cvss,
            "title": title,
            "message": message,
            "cve_data": cve_data,
        }

        # Send to all configured channels
        self._send_to_slack(notification)
        self._send_to_discord(notification)
        self._send_to_generic(notification)
        self._log_to_file(notification)

    def notify_batch_complete(
        self,
        total_cves: int,
        in_scope: int,
        with_exploits: int,
        kev_count: int,
    ) -> None:
        """
        Send notification that a batch assessment completed.

        Args:
            total_cves: Total CVEs assessed
            in_scope: Number in scope
            with_exploits: Number with exploits
            kev_count: Number of KEV-listed
        """
        message = (
            f"Batch CVE assessment complete:\\n"
            f"- Total CVEs: {total_cves}\\n"
            f"- In scope: {in_scope}\\n"
            f"- With exploits: {with_exploits}\\n"
            f"- KEV listed: {kev_count}"
        )

        notification = {
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "level": "INFO",
            "message": message,
            "stats": {
                "total": total_cves,
                "in_scope": in_scope,
                "with_exploits": with_exploits,
                "kev_count": kev_count,
            },
        }

        self._send_to_slack(notification)
        self._send_to_discord(notification)
        self._log_to_file(notification)

    def _send_to_slack(self, notification: dict[str, Any]) -> None:
        """Send notification to Slack webhooks."""
        if not self.webhooks["slack"]:
            return

        color = "#FF0000" if notification.get("level") == "CRITICAL" else "#36A64F"

        for webhook_url in self.webhooks["slack"]:
            if not is_safe_url(webhook_url):
                logger.warning("Blocked unsafe Slack webhook URL: %s", _url_domain(webhook_url))
                continue
            try:
                _post_webhook(webhook_url, {
                    "attachments": [{
                        "color": color,
                        "title": notification.get("cve_id", "CVE Alert"),
                        "text": notification.get("message", ""),
                        "fields": [
                            {
                                "title": "CVSS",
                                "value": str(notification.get("cvss", "N/A")),
                                "short": True,
                            },
                            {
                                "title": "Level",
                                "value": notification.get("level", "INFO"),
                                "short": True,
                            },
                        ],
                        "footer": "PocMap Bug Bounty Toolkit",
                        "ts": int(datetime.now(timezone.utc).timestamp()),
                    }],
                })
            except Exception as e:
                logger.error("Slack notification failed for %s: %s", _url_domain(webhook_url), e)

    def _send_to_discord(self, notification: dict[str, Any]) -> None:
        """Send notification to Discord webhooks."""
        if not self.webhooks["discord"]:
            return

        color = 16711680 if notification.get("level") == "CRITICAL" else 3066993

        for webhook_url in self.webhooks["discord"]:
            if not is_safe_url(webhook_url):
                logger.warning("Blocked unsafe Discord webhook URL: %s", _url_domain(webhook_url))
                continue
            try:
                _post_webhook(webhook_url, {
                    "embeds": [{
                        "title": notification.get("cve_id", "CVE Alert"),
                        "description": notification.get("message", ""),
                        "color": color,
                        "fields": [
                            {
                                "name": "CVSS",
                                "value": str(notification.get("cvss", "N/A")),
                                "inline": True,
                            },
                            {
                                "name": "Severity",
                                "value": notification.get("level", "INFO"),
                                "inline": True,
                            },
                        ],
                        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                        "footer": {"text": "PocMap Bug Bounty Toolkit"},
                    }],
                })
            except Exception as e:
                logger.error("Discord notification failed for %s: %s", _url_domain(webhook_url), e)

    def _send_to_generic(self, notification: dict[str, Any]) -> None:
        """Send notification to generic webhooks."""
        for webhook_url in self.webhooks["generic"]:
            if not is_safe_url(webhook_url):
                logger.warning("Blocked unsafe generic webhook URL: %s", _url_domain(webhook_url))
                continue
            try:
                _post_webhook(webhook_url, notification)
            except Exception as e:
                logger.error("Generic webhook notification failed for %s: %s", _url_domain(webhook_url), e)

    def _log_to_file(self, notification: dict[str, Any]) -> None:
        """Log notification to file."""
        if not self.log_file:
            return

        try:
            safe_log_file = _safe_path(self.log_file)
            with open(safe_log_file, "a") as f:
                f.write(json.dumps(notification) + "\\n")
        except Exception as e:
            print(f"File logging failed: {e}")
