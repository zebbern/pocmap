"""
Vulnerability Prioritization Engine

Provides scoring algorithms and prioritization strategies for CVEs
to help bug bounty hunters focus on the highest-value targets.

Strategies:
    - epss: Prioritize by exploitation probability
    - cvss: Prioritize by CVSS base score
    - kev_first: Prioritize known exploited vulnerabilities
    - exploit_available: Prioritize CVEs with public exploits
    - composite: Weighted combination of all factors

Integration:
    - Uses pocmap.models.CVE for CVE data
    - pocmap.services.cve_service for lookups

Example:
    from pocmap.bugbounty.prioritization import prioritize_cves, calculate_bounty_potential

    sorted_cves = prioritize_cves(cve_list, strategy="composite")
    for cve in sorted_cves[:10]:
        bounty = calculate_bounty_potential(cve)
        print(f"{cve['id']}: score={cve['priority_score']}, bounty_potential={bounty['estimate']}")
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pocmap.utils.compat import get_value


class PriorityStrategy(Enum):
    """Available prioritization strategies."""
    EPSS = "epss"
    CVSS = "cvss"
    KEV_FIRST = "kev_first"
    EXPLOIT_AVAILABLE = "exploit_available"
    COMPOSITE = "composite"
    BOUNTY_POTENTIAL = "bounty_potential"
    TIMELINESS = "timeliness"  # New CVEs first
    EASE_OF_EXPLOITATION = "ease"


# ═══════════════════════════════════════════════════════════════════════════════
# SCORING ALGORITHMS
# ═══════════════════════════════════════════════════════════════════════════════

class ScoringWeights:
    """Configurable weights for composite scoring."""
    # Base vulnerability weights
    CVSS_WEIGHT: float = 0.25
    EPSS_WEIGHT: float = 0.20
    KEV_WEIGHT: float = 0.20
    EXPLOIT_WEIGHT: float = 0.15
    AGE_WEIGHT: float = 0.05
    SCOPE_WEIGHT: float = 0.05
    # Bounty-specific weights
    BOUNTY_PLATFORM_MULTIPLIER: float = 1.0
    SEVERITY_PREMIUM: float = 1.0


def _normalize(value: float, min_val: float = 0.0, max_val: float = 10.0) -> float:
    """Normalize a value to 0-1 range."""
    if max_val == min_val:
        return 0.0
    return max(0.0, min(1.0, (value - min_val) / (max_val - min_val)))


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    if value is None:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


# Shared dict/model accessor from utils.compat. Aliased as ``_get_value`` so the
# many internal call sites below stay unchanged. compat.get_value is a strict
# superset of the previous local copy: it additionally returns the default when
# the object is None (call sites here always pass a CVE dict/model, never None).
_get_value = get_value


def _days_since_published(cve: Any) -> int:
    """Calculate days since CVE was published."""
    published = (
        _get_value(cve, "publication_date")
        or _get_value(cve, "published_date")
        or _get_value(cve, "published")
        or _get_value(cve, "date")
    )
    if not published:
        return 365  # Default to old if unknown
    try:
        if isinstance(published, str):
            # Try common formats
            for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"]:
                try:
                    dt = datetime.strptime(published[:19], fmt)
                    # dt is naive; keep "now" naive too so the subtraction
                    # does not raise on aware/naive mismatch.
                    return (datetime.now(timezone.utc).replace(tzinfo=None) - dt).days
                except ValueError:
                    continue
        return 365
    except Exception:
        return 365


def _has_public_exploit(cve: Any) -> bool:
    """Check if CVE has a public exploit available."""
    # Check multiple possible fields
    exploits = _get_value(cve, "exploits", [])
    exploit_indicators = [
        _get_value(cve, "exploit_available"),
        _get_value(cve, "has_exploit"),
        _get_value(cve, "exploit_poc"),
        _get_value(cve, "github_poc_count", 0) > 0,
        _get_value(cve, "exploitdb_id"),
        _get_value(cve, "metasploit_module"),
        len(exploits) > 0 if isinstance(exploits, list) else False,
    ]
    return any(exploit_indicators)


def _is_kev_listed(cve: Any) -> bool:
    """Check if CVE is on CISA KEV catalog."""
    # For CVEInfo Pydantic models, use the kev_status attribute directly
    if hasattr(cve, "kev_status"):
        return bool(cve.kev_status)
    kev_indicators = [
        cve.get("kev_listed"),
        cve.get("cisa_kev"),
        cve.get("in_kev"),
        cve.get("known_exploited"),
    ]
    return any(kev_indicators)


def _get_cvss_score(cve: Any) -> float:
    """Extract CVSS score from CVE data."""
    # For CVEInfo Pydantic models, access cvss.base_score directly
    if hasattr(cve, "cvss"):
        cvss_obj = cve.cvss
        if hasattr(cvss_obj, "base_score") and cvss_obj.base_score is not None:
            return float(cvss_obj.base_score)
    # Fallback for dict-style access
    for key in ["cvss3_score", "cvss3", "cvss_score", "cvss", "base_score"]:
        val = _safe_float(_get_value(cve, key))
        if val > 0:
            return val
    return 0.0


def _get_epss_score(cve: Any) -> float:
    """Extract EPSS score from CVE data."""
    # For CVEInfo Pydantic models, epss is authoritative on a 0-100 scale;
    # convert to a 0-1 probability. (A magnitude guess mis-scales any CVE
    # whose EPSS percentage is <= 1.)
    if hasattr(cve, "epss") and cve.epss is not None:
        return _safe_float(cve.epss) / 100.0
    # Fallback for dict-style access (scale unknown; keep the best-effort guess)
    for key in ["epss_score", "epss", "epss_probability"]:
        val = _safe_float(_get_value(cve, key))
        if val > 0:
            return val if val <= 1 else val / 100
    return 0.0


def _get_exploit_count(cve: Any) -> int:
    """Get number of available exploits."""
    exploits = _get_value(cve, "exploits", [])
    if isinstance(exploits, list):
        return len(exploits)
    github_count: int = _get_value(cve, "github_poc_count", 0)
    return max(1 if _has_public_exploit(cve) else 0, github_count)


# ═══════════════════════════════════════════════════════════════════════════════
# PRIORITIZATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_cvss_score(cve: Any) -> float:
    """
    Calculate normalized CVSS priority score (0-100).

    Args:
        cve: CVE data dictionary or CVEInfo model

    Returns:
        Normalized score 0-100
    """
    cvss = _get_cvss_score(cve)
    return _normalize(cvss, 0, 10) * 100


def calculate_epss_score(cve: Any) -> float:
    """
    Calculate EPSS-based priority score (0-100).

    Args:
        cve: CVE data dictionary or CVEInfo model

    Returns:
        Normalized score 0-100
    """
    epss = _get_epss_score(cve)
    return epss * 100  # EPSS is already 0-1


def calculate_kev_score(cve: Any) -> float:
    """
    Calculate KEV-based priority score (0-100).

    KEV-listed CVEs get maximum priority.

    Args:
        cve: CVE data dictionary or CVEInfo model

    Returns:
        Score 0-100
    """
    if _is_kev_listed(cve):
        return 100.0
    # Check for indicators of active exploitation
    indicators = [
        _get_value(cve, "active_exploitation"),
        _get_value(cve, "in_the_wild"),
        _get_value(cve, "exploited_in_wild"),
    ]
    if any(indicators):
        return 80.0
    return 0.0


def calculate_exploit_score(cve: Any) -> float:
    """
    Calculate exploit availability score (0-100).

    Considers number and quality of available exploits.

    Args:
        cve: CVE data dictionary or CVEInfo model

    Returns:
        Score 0-100
    """
    if not _has_public_exploit(cve):
        return 0.0

    exploit_count = _get_exploit_count(cve)
    score = min(40 + (exploit_count * 15), 100)

    # Bonus for high-quality exploits
    if _get_value(cve, "metasploit_module"):
        score = min(score + 20, 100)
    if _get_value(cve, "exploitdb_verified"):
        score = min(score + 10, 100)

    return score


def calculate_timeliness_score(cve: Any) -> float:
    """
    Calculate timeliness score - newer CVEs with exploits are gold.

    CVEs published 7-30 days ago with working exploits are
    optimal for bug bounty - organizations haven't patched yet.

    Args:
        cve: CVE data dictionary or CVEInfo model

    Returns:
        Score 0-100
    """
    age_days = _days_since_published(cve)

    # Sweet spot: 7-30 days old (orgs haven't patched, exploits exist)
    if 7 <= age_days <= 30:
        return 100.0
    elif age_days < 7:
        # Very new - exploits may not exist yet
        return 70.0
    elif age_days <= 90:
        return max(0, 100 - ((age_days - 30) * 0.5))
    else:
        return max(0, 50 - ((age_days - 90) * 0.2))


def calculate_composite_score(
    cve: Any,
    weights: ScoringWeights | None = None,
) -> float:
    """
    Calculate composite priority score combining all factors.

    The composite score balances:
    - CVSS severity (25%)
    - EPSS exploitation probability (20%)
    - KEV status (20%)
    - Exploit availability (15%)
    - Timeliness/age (5%)
    - Asset scope relevance (5%)
    - Bounty potential adjustments

    Args:
        cve: CVE data dictionary or CVEInfo model
        weights: Optional custom scoring weights

    Returns:
        Composite score 0-100
    """
    w = weights or ScoringWeights()

    cvss_component = calculate_cvss_score(cve) * w.CVSS_WEIGHT
    epss_component = calculate_epss_score(cve) * w.EPSS_WEIGHT
    kev_component = calculate_kev_score(cve) * w.KEV_WEIGHT
    exploit_component = calculate_exploit_score(cve) * w.EXPLOIT_WEIGHT
    timeliness_component = calculate_timeliness_score(cve) * w.AGE_WEIGHT

    # Scope relevance - higher if target is in scope
    scope_score = 100.0 if _get_value(cve, "in_scope") else 50.0
    scope_component = scope_score * w.SCOPE_WEIGHT

    composite = (
        cvss_component +
        epss_component +
        kev_component +
        exploit_component +
        timeliness_component +
        scope_component
    )

    # Boost for KEV + Exploit combo (actively exploited with working PoC)
    if calculate_kev_score(cve) >= 80 and calculate_exploit_score(cve) >= 40:
        composite = min(composite * 1.15, 100)

    # Penalty for very old CVEs with no recent activity
    age = _days_since_published(cve)
    if age > 365 and not _is_kev_listed(cve):
        composite *= 0.7

    return round(min(composite, 100), 2)


def calculate_bounty_potential(
    cve: Any,
    platform: str = "hackerone",
) -> dict[str, Any]:
    """
    Estimate bug bounty potential for a CVE.

    Analyzes severity, exploitability, and platform to estimate
    realistic bounty ranges.

    Args:
        cve: CVE data dictionary or CVEInfo model
        platform: Bug bounty platform (affects ranges)

    Returns:
        Dictionary with bounty estimation details
    """
    cvss = _get_cvss_score(cve)
    has_exploit = _has_public_exploit(cve)
    is_kev = _is_kev_listed(cve)
    epss = _get_epss_score(cve)

    # Build a searchable text from CVE fields for keyword matching
    title_text = (
        _get_value(cve, "title", "")
        or _get_value(cve, "description", "")
        or _get_value(cve, "id", "")
        or ""
    ).lower()

    # --- Issue 4: Check for RESERVED or REJECTED CVEs ---
    cve_state = _get_value(cve, "state")
    state_name = ""
    if cve_state is not None:
        # Handle both CVEState enum and string values
        state_name = getattr(cve_state, "name", str(cve_state)).upper()

    if state_name in ("RESERVED", "REJECTED"):
        return {
            "severity": "Unknown",
            "cvss_score": cvss,
            "estimated_range_usd": "N/A (insufficient data)",
            "estimated_low": 0,
            "estimated_high": 0,
            "estimated_median": 0,
            "total_multiplier": 0.0,
            "multipliers": {},
            "platform": platform,
            "confidence": "none",
            "key_factors": [f"CVE state is {state_name} — no technical details available"],
            "recommendation": "Insufficient data: This CVE is RESERVED/REJECTED. Wait for publication before assessing bounty potential.",
        }

    # Base severity calculation
    if cvss >= 9.0:
        severity = "Critical"
        base_range = (3000, 15000)
    elif cvss >= 7.0:
        severity = "High"
        base_range = (1000, 5000)
    elif cvss >= 4.0:
        severity = "Medium"
        base_range = (300, 1500)
    else:
        severity = "Low"
        base_range = (100, 500)

    # Multipliers
    multipliers = {
        "exploit_multiplier": 1.5 if has_exploit else 0.7,
        "kev_multiplier": 1.3 if is_kev else 1.0,
        "epss_multiplier": 1.0 + (epss * 0.5),  # 1.0-1.5x
        "rce_multiplier": 2.0 if "rce" in title_text else 1.0,
        "auth_bypass_multiplier": 1.5 if "auth" in title_text else 1.0,
        "data_exposure_multiplier": 1.4 if any(
            x in title_text
            for x in ["sql", "injection", "disclosure", "leak"]
        ) else 1.0,
    }

    # Platform adjustments
    platform_multipliers = {
        "hackerone": 1.2,
        "bugcrowd": 1.0,
        "intigriti": 1.1,
        "synack": 1.3,
        "yeswehack": 0.9,
    }
    platform_mult = platform_multipliers.get(platform.lower(), 1.0)

    total_multiplier = (
        multipliers["exploit_multiplier"] *
        multipliers["kev_multiplier"] *
        multipliers["epss_multiplier"] *
        multipliers["rce_multiplier"] *
        multipliers["auth_bypass_multiplier"] *
        multipliers["data_exposure_multiplier"] *
        platform_mult
    )

    estimated_low = int(base_range[0] * total_multiplier)
    estimated_high = int(base_range[1] * total_multiplier)

    # Realism caps
    max_realistic = {
        "Critical": 50000,
        "High": 15000,
        "Medium": 3000,
        "Low": 1000,
    }
    cap = max_realistic.get(severity, 5000)
    estimated_high = min(estimated_high, cap)
    estimated_low = min(estimated_low, estimated_high)

    return {
        "severity": severity,
        "cvss_score": cvss,
        "estimated_range_usd": f"${estimated_low} - ${estimated_high}",
        "estimated_low": estimated_low,
        "estimated_high": estimated_high,
        "estimated_median": (estimated_low + estimated_high) // 2,
        "total_multiplier": round(total_multiplier, 2),
        "multipliers": multipliers,
        "platform": platform,
        "confidence": "high" if has_exploit and cvss >= 7 else "medium",
        "key_factors": _get_bounty_factors(cve, has_exploit, is_kev),
        "recommendation": _get_bounty_recommendation(cvss, has_exploit, is_kev),
    }


def _get_bounty_factors(cve: Any, has_exploit: bool, is_kev: bool) -> list[str]:
    """Get key factors affecting bounty potential."""
    factors = []
    title = (
        _get_value(cve, "title", "")
        or _get_value(cve, "description", "")
        or _get_value(cve, "id", "")
        or ""
    ).lower()

    if is_kev:
        factors.append("Actively exploited in the wild (KEV)")
    if has_exploit:
        factors.append("Public exploit available")
    if _get_cvss_score(cve) >= 9.0:
        factors.append("Critical severity (CVSS 9.0+)")
    if "rce" in title:
        factors.append("Remote Code Execution potential")
    if "auth" in title or "bypass" in title:
        factors.append("Authentication bypass potential")
    if "sql" in title or "injection" in title:
        factors.append("Data access potential")
    if "ssrf" in title:
        factors.append("Server-Side Request Forgery")
    if _get_epss_score(cve) > 0.5:
        factors.append("High exploitation probability (EPSS)")

    return factors


def _get_bounty_recommendation(cvss: float, has_exploit: bool, is_kev: bool) -> str:
    """Get bounty strategy recommendation."""
    if cvss >= 9 and has_exploit:
        return "HIGH PRIORITY: Critical CVE with exploit. Submit immediately - this is peak bounty material."
    elif cvss >= 7 and has_exploit:
        return "Good opportunity: High severity CVE with working exploit. Solid bounty expected."
    elif is_kev and has_exploit:
        return "Good opportunity: KEV-listed CVE with exploit. Organizations actively patching."
    elif cvss >= 7 and not has_exploit:
        return "DEVELOP EXPLOIT: High severity but no public exploit. Developing one could yield high bounty."
    elif has_exploit and cvss >= 4:
        return "Quick win: Medium severity with exploit. Fast turnaround, reliable payout."
    else:
        return "Lower priority: Consider focusing on higher-impact CVEs unless this is in a critical path."


def threat_model(cve: Any, asset_info: dict[str, Any]) -> dict[str, Any]:
    """
    Simple threat model for a CVE against a specific asset.

    Args:
        cve: CVE data dictionary or CVEInfo model
        asset_info: Asset information dictionary with keys like:
            - name: Asset name
            - type: (web_app, api, database, etc.)
            - exposure: (internet, intranet, internal)
            - criticality: (critical, high, medium, low)
            - data_classification: (public, internal, confidential, restricted)
            - auth_required: bool
            - user_count: approximate user count

    Returns:
        Threat model with risk scores and attack scenarios
    """
    cvss = _get_cvss_score(cve)
    has_exploit = _has_public_exploit(cve)
    is_kev = _is_kev_listed(cve)

    # Asset criticality multiplier
    criticality_map = {
        "critical": 1.5, "high": 1.3, "medium": 1.0, "low": 0.7
    }
    asset_criticality = criticality_map.get(
        asset_info.get("criticality", "medium").lower(), 1.0
    )

    # Exposure multiplier
    exposure_map = {
        "internet": 1.5, "intranet": 1.1, "internal": 0.7
    }
    exposure_mult = exposure_map.get(
        asset_info.get("exposure", "internal").lower(), 1.0
    )

    # Data classification multiplier
    data_map = {
        "restricted": 1.5, "confidential": 1.3, "internal": 1.0, "public": 0.5
    }
    data_mult = data_map.get(
        asset_info.get("data_classification", "internal").lower(), 1.0
    )

    # Calculate risk score
    base_risk = cvss * 10  # 0-100
    exploit_mult = 1.5 if has_exploit else 0.8
    kev_mult = 1.3 if is_kev else 1.0

    risk_score = round(
        base_risk * exploit_mult * kev_mult *
        asset_criticality * exposure_mult * data_mult,
        2,
    )
    risk_score = min(risk_score, 100)

    # Determine risk level
    if risk_score >= 80:
        risk_level = "Critical"
    elif risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    elif risk_score >= 20:
        risk_level = "Low"
    else:
        risk_level = "Minimal"

    # Generate attack scenarios
    scenarios = _generate_attack_scenarios(cve, asset_info, has_exploit)

    # Calculate business impact
    user_count = asset_info.get("user_count", 0)
    business_impact = _calculate_business_impact(
        risk_level, asset_info, user_count
    )

    cve_id = (
        _get_value(cve, "id")
        or _get_value(cve, "cve_id")
        or "Unknown"
    )

    return {
        "cve_id": cve_id,
        "asset_name": asset_info.get("name", "Unknown"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "likelihood": _calculate_likelihood(cvss, has_exploit, is_kev),
        "impact": _calculate_impact(asset_info),
        "attack_scenarios": scenarios,
        "business_impact": business_impact,
        "mitigations": _suggest_mitigations(cve, asset_info),
        "monitoring_recommendations": _suggest_monitoring(cve),
        "remediation_priority": "immediate" if risk_score >= 80 else (
            "high" if risk_score >= 60 else "medium"
        ),
    }


def _calculate_likelihood(cvss: float, has_exploit: bool, is_kev: bool) -> dict[str, Any]:
    """Calculate attack likelihood."""
    score = cvss / 10  # 0-1
    if has_exploit:
        score += 0.2
    if is_kev:
        score += 0.3
    score = min(score, 1.0)

    if score >= 0.8:
        level = "Very High"
    elif score >= 0.6:
        level = "High"
    elif score >= 0.4:
        level = "Medium"
    elif score >= 0.2:
        level = "Low"
    else:
        level = "Very Low"

    return {"score": round(score, 2), "level": level}


def _calculate_impact(asset_info: dict[str, Any]) -> dict[str, Any]:
    """Calculate business impact."""
    criticality = asset_info.get("criticality", "medium").lower()
    data_class = asset_info.get("data_classification", "internal").lower()

    impact_map = {
        "critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3
    }
    data_impact = {
        "restricted": 0.9, "confidential": 0.7, "internal": 0.5, "public": 0.2
    }

    score = (impact_map.get(criticality, 0.5) + data_impact.get(data_class, 0.5)) / 2

    if score >= 0.8:
        level = "Severe"
    elif score >= 0.6:
        level = "High"
    elif score >= 0.4:
        level = "Medium"
    else:
        level = "Low"

    return {"score": round(score, 2), "level": level}


def _generate_attack_scenarios(
    cve: Any, asset_info: dict[str, Any], has_exploit: bool
) -> list[dict[str, Any]]:
    """Generate plausible attack scenarios."""
    scenarios = []
    title = (
        _get_value(cve, "title", "")
        or _get_value(cve, "description", "")
        or _get_value(cve, "id", "")
        or ""
    ).lower()

    # RCE scenarios
    if any(x in title for x in ["rce", "remote code", "command injection", "deserialization"]):
        scenarios.append({
            "name": "Remote Code Execution",
            "description": "Attacker executes arbitrary commands on the server",
            "prerequisites": ["Network access to target", "Vulnerable endpoint accessible"],
            "impact": "Full server compromise, data exfiltration, lateral movement",
            "complexity": "Low" if has_exploit else "Medium",
        })

    # SQL Injection scenarios
    if any(x in title for x in ["sql injection", "sqli", "blind sql"]):
        scenarios.append({
            "name": "Data Exfiltration",
            "description": "Attacker extracts sensitive data from database",
            "prerequisites": ["Vulnerable input parameter", "Database accessible from application"],
            "impact": "Complete database compromise, PII exposure",
            "complexity": "Low" if has_exploit else "Medium",
        })

    # Auth bypass
    if any(x in title for x in ["auth bypass", "authentication", "privilege escalation"]):
        scenarios.append({
            "name": "Unauthorized Access",
            "description": "Attacker gains access without valid credentials",
            "prerequisites": ["Access to authentication mechanism"],
            "impact": "Access to restricted functionality and data",
            "complexity": "Low" if has_exploit else "Medium",
        })

    # SSRF
    if "ssrf" in title:
        scenarios.append({
            "name": "Internal Network Reconnaissance",
            "description": "Attacker accesses internal services through the server",
            "prerequisites": ["URL input parameter vulnerable"],
            "impact": "Access to internal APIs, cloud metadata, internal infrastructure",
            "complexity": "Medium",
        })

    # XSS
    if any(x in title for x in ["xss", "cross-site scripting"]):
        scenarios.append({
            "name": "Session Hijacking",
            "description": "Attacker steals user sessions or performs actions on behalf of victims",
            "prerequisites": ["User visits malicious link"],
            "impact": "Account takeover, data theft, unauthorized actions",
            "complexity": "Low",
        })

    # Default scenario
    if not scenarios:
        cve_id = _get_value(cve, "id") or _get_value(cve, "cve_id") or "the vulnerability"
        scenarios.append({
            "name": "Vulnerability Exploitation",
            "description": f"Attacker exploits {cve_id}",
            "prerequisites": ["Network access", "Vulnerable instance identified"],
            "impact": "Depends on specific vulnerability capabilities",
            "complexity": "Low" if has_exploit else "High",
        })

    return scenarios


def _calculate_business_impact(
    risk_level: str, asset_info: dict[str, Any], user_count: int
) -> dict[str, Any]:
    """Calculate business impact assessment."""
    impacts = []

    if risk_level in ["Critical", "High"]:
        impacts.append("Potential regulatory fines (GDPR, CCPA)")
        impacts.append("Reputational damage and customer trust loss")

    if asset_info.get("data_classification") in ["confidential", "restricted"]:
        impacts.append("Sensitive data exposure")

    if user_count > 100000:
        impacts.append("Large user base affected")
    elif user_count > 10000:
        impacts.append("Moderate user base affected")

    if asset_info.get("criticality") == "critical":
        impacts.append("Core business function disruption")

    return {
        "summary": impacts,
        "user_count_affected": user_count,
        "estimated_downtime_hours": 4 if risk_level == "Critical" else (
            2 if risk_level == "High" else 0.5
        ),
        "compliance_implications": _get_compliance_implications(asset_info),
    }


def _get_compliance_implications(asset_info: dict[str, Any]) -> list[str]:
    """Get compliance implications based on asset info."""
    implications = []
    data_class = asset_info.get("data_classification", "").lower()

    if data_class in ["confidential", "restricted"]:
        implications.append("GDPR Article 32 - Security of processing")
        implications.append("Potential breach notification requirement")
    if asset_info.get("type", "").lower() == "payment":
        implications.append("PCI-DSS Requirement 6.2 - Patch management")
    if data_class == "restricted":
        implications.append("SOC 2 CC7.1 - Security detection")

    return implications


def _suggest_mitigations(cve: Any, asset_info: dict[str, Any]) -> list[str]:
    """Suggest mitigations for the vulnerability."""
    mitigations = [
        "Apply vendor patch immediately",
        "Implement virtual patching via WAF",
        "Restrict network access to vulnerable endpoints",
    ]

    if asset_info.get("type") == "web_app":
        mitigations.append("Enable additional input validation")

    if _has_public_exploit(cve):
        mitigations.append("Deploy IDS/IPS signatures for exploit detection")

    return mitigations


def _suggest_monitoring(cve: Any) -> list[str]:
    """Suggest monitoring for exploitation attempts."""
    monitoring = [
        "Monitor logs for anomalous requests to vulnerable endpoints",
        "Set up alerts for CVE-related indicators of compromise",
    ]

    if _is_kev_listed(cve):
        monitoring.append("Priority monitoring - CVE is on CISA KEV catalog")
        monitoring.append("Review threat intelligence feeds for active campaigns")

    return monitoring


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN PRIORITIZATION FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════

def prioritize_cves(
    cves: list[Any],
    strategy: str = "composite",
    weights: ScoringWeights | None = None,
    min_cvss: float = 0.0,
    require_exploit: bool = False,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """
    Sort and prioritize a list of CVEs by the specified strategy.

    Args:
        cves: List of CVE data dictionaries or CVEInfo models
        strategy: Sorting strategy - one of:
            - epss: Sort by exploitation probability
            - cvss: Sort by CVSS base score
            - kev_first: KEV-listed first, then by CVSS
            - exploit_available: CVEs with exploits first
            - composite: Weighted combination (default)
            - bounty_potential: Estimated bounty value
            - timeliness: Newer CVEs first
            - ease: Easiest to exploit first
        weights: Custom scoring weights for composite strategy
        min_cvss: Filter out CVEs below this CVSS score
        require_exploit: Only include CVEs with known exploits
        limit: Maximum number of results to return

    Returns:
        Sorted list of CVE dictionaries with 'priority_score' added

    Example:
        cves = [
            {"id": "CVE-2021-44228", "cvss": 10.0, "epss": 0.95, "kev": True},
            {"id": "CVE-2023-1234", "cvss": 7.5, "epss": 0.3, "exploit": True},
        ]
        prioritized = prioritize_cves(cves, strategy="composite")
        # Returns sorted list with priority_score added to each
    """
    strategy_enum = PriorityStrategy(strategy.lower())

    # Filter
    filtered = []
    for cve in cves:
        if _get_cvss_score(cve) < min_cvss:
            continue
        if require_exploit and not _has_public_exploit(cve):
            continue
        filtered.append(cve)

    # Score each CVE
    scored = []
    for cve in filtered:
        # Handle both dicts and Pydantic models
        cve_copy = cve.model_dump(mode="json") if hasattr(cve, "model_dump") else dict(cve)

        if strategy_enum == PriorityStrategy.EPSS:
            cve_copy["priority_score"] = calculate_epss_score(cve)
        elif strategy_enum == PriorityStrategy.CVSS:
            cve_copy["priority_score"] = calculate_cvss_score(cve)
        elif strategy_enum == PriorityStrategy.KEV_FIRST:
            kev_score = calculate_kev_score(cve)
            cvss_score = calculate_cvss_score(cve)
            cve_copy["priority_score"] = kev_score * 0.6 + cvss_score * 0.4
        elif strategy_enum == PriorityStrategy.EXPLOIT_AVAILABLE:
            cve_copy["priority_score"] = calculate_exploit_score(cve)
        elif strategy_enum == PriorityStrategy.TIMELINESS:
            cve_copy["priority_score"] = calculate_timeliness_score(cve)
        elif strategy_enum == PriorityStrategy.EASE_OF_EXPLOITATION:
            exploit_score = calculate_exploit_score(cve)
            cvss_score = calculate_cvss_score(cve)
            # Easy = high exploit score + medium CVSS (not too complex)
            cve_copy["priority_score"] = exploit_score * 0.7 + (100 - cvss_score) * 0.3
        elif strategy_enum == PriorityStrategy.BOUNTY_POTENTIAL:
            bounty = calculate_bounty_potential(cve)
            cve_copy["priority_score"] = bounty["estimated_median"] / 100
        elif strategy_enum == PriorityStrategy.COMPOSITE:
            cve_copy["priority_score"] = calculate_composite_score(cve, weights)
        else:
            cve_copy["priority_score"] = calculate_composite_score(cve, weights)

        scored.append(cve_copy)

    # Sort by priority score descending
    sorted_cves = sorted(scored, key=lambda x: x["priority_score"], reverse=True)

    if limit:
        sorted_cves = sorted_cves[:limit]

    return sorted_cves


def get_priority_tiers(cves: list[Any]) -> dict[str, Any]:
    """
    Group CVEs into priority tiers for action planning.

    Args:
        cves: List of scored CVE dictionaries (with priority_score)

    Returns:
        Dictionary with tier groupings
    """
    tiers: dict[str, list[Any]] = {
        "p0_drop_everything": [],  # Score 90-100
        "p1_act_today": [],        # Score 75-89
        "p2_act_this_week": [],    # Score 60-74
        "p3_plan_for": [],         # Score 40-59
        "p4_monitor": [],          # Score < 40
    }

    for cve in cves:
        score = _get_value(cve, "priority_score", 0)
        # If no priority_score, compute from cvss
        if score == 0:
            cvss = _get_cvss_score(cve)
            epss = _get_epss_score(cve)
            score = min(100, int(cvss * 10 + epss * 0.1))
        if score >= 90:
            tiers["p0_drop_everything"].append(cve)
        elif score >= 75:
            tiers["p1_act_today"].append(cve)
        elif score >= 60:
            tiers["p2_act_this_week"].append(cve)
        elif score >= 40:
            tiers["p3_plan_for"].append(cve)
        else:
            tiers["p4_monitor"].append(cve)

    return tiers


def export_prioritized_list(
    cves: list[Any],
    filepath: str,
    format: str = "json",
) -> None:
    """
    Export prioritized CVE list to file.

    Args:
        cves: Prioritized CVE list (dicts or CVEInfo models)
        filepath: Output file path
        format: Output format (json, csv, markdown)
    """
    if format == "json":
        with open(filepath, "w") as f:
            json.dump(cves, f, indent=2, default=str)
    elif format == "markdown":
        lines = [
            "# Prioritized Vulnerability List",
            "",
            "| Rank | CVE ID | Severity | CVSS | EPSS | KEV | Exploit | Score |",
            "|------|--------|----------|------|------|-----|---------|-------|",
        ]
        for i, cve in enumerate(cves[:50], 1):
            cve_id = (
                _get_value(cve, "id")
                or _get_value(cve, "cve_id")
                or "N/A"
            )
            lines.append(
                f"| {i} | {cve_id} | "
                f"{_get_value(cve, 'severity', 'N/A')} | "
                f"{_get_cvss_score(cve):.1f} | "
                f"{_get_epss_score(cve):.2f} | "
                f"{'Yes' if _is_kev_listed(cve) else 'No'} | "
                f"{'Yes' if _has_public_exploit(cve) else 'No'} | "
                f"{_get_value(cve, 'priority_score', 0):.1f} |"
            )
        with open(filepath, "w") as f:
            f.write("\n".join(lines))
    elif format == "csv":
        import csv
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "rank", "cve_id", "severity", "cvss", "epss",
                "kev", "exploit_available", "priority_score",
            ])
            for i, cve in enumerate(cves, 1):
                cve_id = (
                    _get_value(cve, "id")
                    or _get_value(cve, "cve_id")
                    or ""
                )
                writer.writerow([
                    i,
                    cve_id,
                    _get_value(cve, "severity", ""),
                    _get_cvss_score(cve),
                    _get_epss_score(cve),
                    "Yes" if _is_kev_listed(cve) else "No",
                    "Yes" if _has_public_exploit(cve) else "No",
                    _get_value(cve, "priority_score", 0),
                ])
