"""
Bug Bounty Report Templates

Provides platform-specific report templates (HackerOne, Bugcrowd, Intigriti,
Internal, Executive Summary) with Python functions to render them with CVE data.

Integration:
    - Uses pocmap.models.CVE for CVE data injection
    - Integrates with pocmap.services.cve_service for metadata

Example:
    template = HackerOneTemplate()
    report = template.render(cve_data=cve_info, impact="RCE achieved")
    with open("report.md", "w") as f:
        f.write(report)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pocmap.utils.compat import get_value as _get_value
from pocmap.utils.paths import safe_path

# SECURITY: Use sandboxed Jinja2 environment to prevent SSTI.
# Always import BaseLoader / select_autoescape at module level first.
try:
    from jinja2 import BaseLoader, select_autoescape
except ImportError:
    BaseLoader = None  # type: ignore
    select_autoescape = None  # type: ignore

# Try to create a SandboxedEnvironment (best security); fall back to plain Environment.
# Typed as Any because the concrete class depends on optional jinja2 imports above.
jinja_env: Any = None
try:
    if BaseLoader is not None and select_autoescape is not None:
        from jinja2.sandbox import SandboxedEnvironment

        jinja_env = SandboxedEnvironment(
            loader=BaseLoader(),
            autoescape=select_autoescape(["html", "xml"]),
            enable_async=False,
        )
except ImportError:
    pass

if jinja_env is None and BaseLoader is not None and select_autoescape is not None:
    from jinja2 import Environment

    jinja_env = Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(["html", "xml"]),
        enable_async=False,
    )

# Fallback in case jinja2 is not installed at all
try:
    from jinja2 import Template
except ImportError:
    Template = None  # type: ignore


@dataclass
class TemplateConfig:
    """Configuration for report template rendering."""
    researcher_name: str = ""
    researcher_handle: str = ""
    program_name: str = ""
    target_url: str = ""
    platform: str = "hackerone"  # hackerone, bugcrowd, intigriti, internal
    disclose_identity: bool = False
    include_poc: bool = True
    include_timeline: bool = True
    include_remediation: bool = True
    severity_override: str = ""  # Override auto-calculated severity


def _jinja_render(template_str: str, context: dict[str, Any]) -> str:
    """Render a Jinja2 template string with context (sandboxed)."""
    if jinja_env is None:
        raise ImportError("jinja2 is required for template rendering. Install with: pip install jinja2")
    template = jinja_env.from_string(template_str)
    rendered: str = template.render(**context)
    return rendered


def _simple_render(template_str: str, context: dict[str, Any]) -> str:
    """Simple string replacement fallback when Jinja2 is not available."""
    result = template_str
    for key, value in context.items():
        placeholder = f"{{{{ {key} }}}}"
        if isinstance(value, (list, dict)):
            value = json.dumps(value, indent=2) if value else "N/A"
        result = result.replace(placeholder, str(value) if value is not None else "N/A")
    return result


def render_template(template_str: str, context: dict[str, Any]) -> str:
    """Render template with Jinja2 if available, fallback to simple replacement."""
    try:
        return _jinja_render(template_str, context)
    except ImportError:
        return _simple_render(template_str, context)


# ═══════════════════════════════════════════════════════════════════════════════
# HACKERONE TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════

HACKERONE_TEMPLATE = """# Vulnerability Report: {{ title }}

**Reported by:** {{ researcher_name }} ({{ researcher_handle }})
**Date:** {{ report_date }}
**Severity:** {{ severity }} (CVSS: {{ cvss_score }})
**Asset:** {{ target_url }}
**CVE Reference:** {{ cve_id }}

---

## Executive Summary

{{ executive_summary }}

This vulnerability affects **{{ affected_product }}** versions **{{ affected_versions }}**. The issue is tracked as **{{ cve_id }}** with a CVSS base score of **{{ cvss_score }}**.

---

## Technical Details

### Vulnerability Information

| Field | Value |
|-------|-------|
| CVE ID | {{ cve_id }} |
| CWE | {{ cwe_id }} |
| CVSS Score | {{ cvss_score }} |
| EPSS Score | {{ epss_score }} |
| KEV Listed | {{ kev_listed }} |
| Affected Product | {{ affected_product }} |
| Affected Versions | {{ affected_versions }} |
| Fixed Version | {{ fixed_version }} |

### Root Cause

{{ root_cause }}

### Attack Vector

{{ attack_vector }}

{% if attack_scenario %}
### Attack Scenario

{{ attack_scenario }}
{% endif %}

---

## Proof of Concept

{% if poc_summary %}
### PoC Summary

{{ poc_summary }}
{% endif %}

### Steps to Reproduce

{{ reproduction_steps }}

{% if poc_code %}
### PoC Code

```{{ poc_language | default('python') }}
{{ poc_code }}
```
{% endif %}

{% if screenshots %}
### Evidence

{{ screenshots }}
{% endif %}

---

## Impact

{{ impact_description }}

{% if data_exposed %}
### Data at Risk

{{ data_exposed }}
{% endif %}

{% if blast_radius %}
### Blast Radius

{{ blast_radius }}
{% endif %}

---

## CVSS Calculation

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector (AV) | {{ av }} | {{ av_justification }} |
| Attack Complexity (AC) | {{ ac }} | {{ ac_justification }} |
| Privileges Required (PR) | {{ pr }} | {{ pr_justification }} |
| User Interaction (UI) | {{ ui }} | {{ ui_justification }} |
| Scope (S) | {{ s }} | {{ s_justification }} |
| Confidentiality (C) | {{ c }} | {{ c_justification }} |
| Integrity (I) | {{ i }} | {{ i_justification }} |
| Availability (A) | {{ a }} | {{ a_justification }} |

**Base Score:** {{ cvss_score }}

---

## Remediation

### Recommended Fix

{{ remediation_primary }}

{% if remediation_alternative %}
### Alternative Fix

{{ remediation_alternative }}
{% endif %}

### Temporary Mitigations

{{ temporary_mitigations }}

### References

{{ references }}

---

{% if timeline %}
## Timeline

{{ timeline }}
{% endif %}

---

## Disclaimer

{% if disclose_identity %}
I, {{ researcher_name }}, am submitting this report in good faith. I have followed responsible disclosure practices and provided reasonable time for remediation before any public disclosure.
{% else %}
This report is submitted in good faith following responsible disclosure practices. Reasonable time for remediation will be provided before any public disclosure.
{% endif %}

---

*Generated with PocMap Bug Bounty Toolkit*
"""


# ═══════════════════════════════════════════════════════════════════════════════
# BUGCROWD TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════

BUGCROWD_TEMPLATE = """# Bugcrowd Submission: {{ title }}

## Submission Details

**Vulnerability Type:** {{ vuln_type }}
**Severity:** {{ severity }}
**Affected Asset:** {{ target_url }}
**CVE Reference:** {{ cve_id }}
**Bugcrowd Username:** {{ researcher_handle }}

---

## Summary

{{ executive_summary }}

---

## Description

{{ vulnerability_description }}

This issue is classified as **{{ cve_id }}** and affects:
- **Product:** {{ affected_product }}
- **Affected Versions:** {{ affected_versions }}
- **Fixed Version:** {{ fixed_version }}
- **CVSS v3.1 Score:** {{ cvss_score }}

---

## Environment

| Component | Version/Details |
|-----------|----------------|
| Target URL | {{ target_url }} |
| Affected Product | {{ affected_product }} |
| Affected Version | {{ target_version }} |
| CVE ID | {{ cve_id }} |

---

## Steps to Reproduce

{{ reproduction_steps }}

---

## Proof of Concept

{% if poc_code %}
```
{{ poc_code }}
```
{% endif %}

{% if poc_commands %}
### Commands Used

{{ poc_commands }}
{% endif %}

---

## Impact Assessment

{{ impact_description }}

**Business Impact:** {{ business_impact }}

{% if data_at_risk %}
**Data at Risk:** {{ data_at_risk }}
{% endif %}

---

## Suggested Fix

{{ remediation_primary }}

{% if remediation_timeline %}
**Recommended Timeline:** {{ remediation_timeline }}
{% endif %}

---

## References

{{ references }}

{% if additional_notes %}
---

## Additional Notes

{{ additional_notes }}
{% endif %}

---

*Report generated via PocMap Bug Bounty Toolkit*
"""


# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL ASSESSMENT TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════

INTERNAL_ASSESSMENT_TEMPLATE = """# Internal Security Assessment Report

**Classification:** CONFIDENTIAL
**Assessment Date:** {{ report_date }}
**Assessor:** {{ researcher_name }}
**Target System:** {{ target_url }}
**Department/Owner:** {{ department_owner }}
**Report ID:** {{ report_id }}

---

## 1. Executive Summary

{{ executive_summary }}

### Key Findings at a Glance

| CVE ID | Severity | CVSS | EPSS | Exploit Available | Status |
|--------|----------|------|------|-------------------|--------|
{% for cve in cve_list %}
| {{ cve.id }} | {{ cve.severity }} | {{ cve.cvss }} | {{ cve.epss }} | {{ cve.exploit_available }} | {{ cve.status }} |
{% endfor %}

### Risk Rating

**Overall Risk:** {{ overall_risk }}

---

## 2. Vulnerability Details

### 2.1 {{ cve_id }}

#### Overview

- **CVE ID:** {{ cve_id }}
- **CWE:** {{ cwe_id }}
- **CVSS Base Score:** {{ cvss_score }}
- **CVSS Vector:** {{ cvss_vector }}
- **EPSS Score:** {{ epss_score }}
- **CISA KEV:** {{ kev_listed }}
- **Affected Product:** {{ affected_product }}
- **Affected Versions:** {{ affected_versions }}
- **Fixed Version:** {{ fixed_version }}

#### Technical Description

{{ vulnerability_description }}

#### Root Cause Analysis

{{ root_cause }}

#### Attack Prerequisites

{{ attack_prerequisites }}

---

## 3. Affected Assets

| Asset | IP/URL | Version | Exposure | Notes |
|-------|--------|---------|----------|-------|
{% for asset in affected_assets %}
| {{ asset.name }} | {{ asset.location }} | {{ asset.version }} | {{ asset.exposure }} | {{ asset.notes }} |
{% endfor %}

---

## 4. Exploitation Details

### 4.1 Proof of Concept

{{ poc_summary }}

### 4.2 Reproduction Steps

{{ reproduction_steps }}

{% if poc_code %}
### 4.3 Exploit Code

```{{ poc_language | default('python') }}
{{ poc_code }}
```
{% endif %}

### 4.4 Evidence

{{ evidence_description }}

---

## 5. Impact Analysis

### 5.1 Direct Impact

{{ direct_impact }}

### 5.2 Indirect Impact

{{ indirect_impact }}

### 5.3 Compliance Impact

{% if compliance_impact %}
{{ compliance_impact }}
{% else %}
This vulnerability may have implications for compliance frameworks including PCI-DSS, SOC 2, and ISO 27001 if exploited to access cardholder data or sensitive systems.
{% endif %}

---

## 6. Remediation Plan

### 6.1 Immediate Actions (0-7 days)

{{ immediate_actions }}

### 6.2 Short-term Actions (7-30 days)

{{ short_term_actions }}

### 6.3 Long-term Actions (30+ days)

{{ long_term_actions }}

### 6.4 Compensating Controls

{{ compensating_controls }}

---

## 7. References

{{ references }}

---

## 8. Appendix

### CVSS Detailed Calculation

{{ cvss_calculation_details }}

### Tools Used

{{ tools_used }}

### Timeline

{{ timeline }}

---

*This report contains confidential security information. Distribution should be limited to authorized personnel only.*

*Generated with PocMap Bug Bounty Toolkit v1.0*
"""


# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTIVE SUMMARY TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════

EXECUTIVE_SUMMARY_TEMPLATE = """# Executive Security Briefing

**Date:** {{ report_date }}
**Prepared For:** {{ executive_audience }}
**Classification:** {{ classification }}
**Prepared By:** {{ researcher_name }}

---

## TL;DR

{{ tldr }}

---

## The Bottom Line

{{ bottom_line }}

---

## Risk Overview

| Metric | Value |
|--------|-------|
| Critical CVEs Found | {{ critical_count }} |
| High CVEs Found | {{ high_count }} |
| Medium CVEs Found | {{ medium_count }} |
| Exploitable in Wild (KEV) | {{ kev_count }} |
| Systems Affected | {{ systems_affected }} |
| Estimated Fix Time | {{ estimated_fix_time }} |
| Potential Business Impact | {{ business_impact_level }} |

---

## What Could Go Wrong

{{ risk_scenarios }}

---

## What We Recommend

{{ recommendations }}

---

## Investment Required

| Item | Estimated Cost | Timeline |
|------|---------------|----------|
| Emergency Patching | {{ emergency_patch_cost }} | {{ emergency_patch_timeline }} |
| WAF Rules | {{ waf_cost }} | {{ waf_timeline }} |
| Full Remediation | {{ full_remediation_cost }} | {{ full_remediation_timeline }} |

---

## Next Steps

{{ next_steps }}

---

*Questions? Contact {{ researcher_name }} at {{ researcher_contact }}*

*Generated with PocMap Bug Bounty Toolkit*
"""


# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATE CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class BaseTemplate:
    """Base class for all report templates."""

    TEMPLATE_STRING: str = ""
    PLATFORM: str = "generic"

    def __init__(self, config: TemplateConfig | None = None):
        self.config = config or TemplateConfig()

    def _build_context(self, **kwargs: Any) -> dict[str, Any]:
        """Build template context from CVE data and overrides."""
        context = {
            # Default values
            "report_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "researcher_name": self.config.researcher_name,
            "researcher_handle": self.config.researcher_handle,
            "program_name": self.config.program_name,
            "target_url": self.config.target_url,
            "disclose_identity": self.config.disclose_identity,
            # CVE data (with defaults)
            "title": kwargs.get("title", "Untitled Vulnerability Report"),
            "cve_id": kwargs.get("cve_id", "CVE-YYYY-XXXXX"),
            "cwe_id": kwargs.get("cwe_id", "CWE-XXX"),
            "cvss_score": kwargs.get("cvss_score", "N/A"),
            "cvss_vector": kwargs.get("cvss_vector", ""),
            "epss_score": kwargs.get("epss_score", "N/A"),
            "kev_listed": kwargs.get("kev_listed", "Unknown"),
            "severity": kwargs.get("severity", "Unknown"),
            "vuln_type": kwargs.get("vuln_type", "Unknown"),
            "affected_product": kwargs.get("affected_product", "Unknown"),
            "affected_versions": kwargs.get("affected_versions", "Unknown"),
            "fixed_version": kwargs.get("fixed_version", "Unknown"),
            "target_version": kwargs.get("target_version", "Unknown"),
            # Content
            "executive_summary": kwargs.get("executive_summary", ""),
            "vulnerability_description": kwargs.get(
                "vulnerability_description", ""
            ),
            "root_cause": kwargs.get("root_cause", ""),
            "attack_vector": kwargs.get("attack_vector", ""),
            "attack_scenario": kwargs.get("attack_scenario", ""),
            "attack_prerequisites": kwargs.get("attack_prerequisites", ""),
            "reproduction_steps": kwargs.get("reproduction_steps", ""),
            "poc_summary": kwargs.get("poc_summary", ""),
            "poc_code": kwargs.get("poc_code", ""),
            "poc_commands": kwargs.get("poc_commands", ""),
            "poc_language": kwargs.get("poc_language", "python"),
            "screenshots": kwargs.get("screenshots", ""),
            "impact_description": kwargs.get("impact_description", ""),
            "business_impact": kwargs.get("business_impact", ""),
            "data_exposed": kwargs.get("data_exposed", ""),
            "data_at_risk": kwargs.get("data_at_risk", ""),
            "blast_radius": kwargs.get("blast_radius", ""),
            "direct_impact": kwargs.get("direct_impact", ""),
            "indirect_impact": kwargs.get("indirect_impact", ""),
            "compliance_impact": kwargs.get("compliance_impact", ""),
            # CVSS metrics
            "av": kwargs.get("av", "N"),
            "av_justification": kwargs.get("av_justification", ""),
            "ac": kwargs.get("ac", "L"),
            "ac_justification": kwargs.get("ac_justification", ""),
            "pr": kwargs.get("pr", "N"),
            "pr_justification": kwargs.get("pr_justification", ""),
            "ui": kwargs.get("ui", "N"),
            "ui_justification": kwargs.get("ui_justification", ""),
            "s": kwargs.get("s", "U"),
            "s_justification": kwargs.get("s_justification", ""),
            "c": kwargs.get("c", "N"),
            "c_justification": kwargs.get("c_justification", ""),
            "i": kwargs.get("i", "N"),
            "i_justification": kwargs.get("i_justification", ""),
            "a": kwargs.get("a", "N"),
            "a_justification": kwargs.get("a_justification", ""),
            # Remediation
            "remediation_primary": kwargs.get("remediation_primary", ""),
            "remediation_alternative": kwargs.get("remediation_alternative", ""),
            "temporary_mitigations": kwargs.get("temporary_mitigations", ""),
            "remediation_timeline": kwargs.get("remediation_timeline", ""),
            "references": kwargs.get("references", ""),
            # Timeline
            "timeline": kwargs.get("timeline", ""),
            # Extra
            "additional_notes": kwargs.get("additional_notes", ""),
            **kwargs,  # Include any additional fields
        }
        return context

    def render(self, **kwargs: Any) -> str:
        """
        Render the template with provided data.

        Args:
            **kwargs: Template variables. Key ones include:
                - cve_id: CVE identifier
                - cvss_score: CVSS base score
                - executive_summary: Brief summary
                - impact_description: Impact details
                - reproduction_steps: Steps to reproduce
                - remediation_primary: Primary fix recommendation

        Returns:
            Rendered template string
        """
        context = self._build_context(**kwargs)
        return render_template(self.TEMPLATE_STRING, context)

    def render_to_file(self, filepath: str, **kwargs: Any) -> None:
        """Render template and save to file."""
        safe_filepath = safe_path(filepath)
        content = self.render(**kwargs)
        with open(safe_filepath, "w") as f:
            f.write(content)

    def get_required_fields(self) -> list[str]:
        """Get list of fields that should be provided for best results."""
        return [
            "cve_id", "title", "severity", "cvss_score",
            "executive_summary", "vulnerability_description",
            "reproduction_steps", "impact_description",
            "remediation_primary", "affected_product",
        ]

    def validate_context(self, context: dict[str, Any]) -> list[str]:
        """Validate that required fields are present."""
        missing = []
        for field in self.get_required_fields():
            if not context.get(field):
                missing.append(field)
        return missing

    @classmethod
    def from_cve_data(cls, cve_data: dict[str, Any], config: TemplateConfig | None = None) -> str:
        """
        Create a report from structured CVE data.

        Args:
            cve_data: Dictionary with CVE information from pocmap
            config: Optional template configuration

        Returns:
            Rendered report string
        """
        instance = cls(config=config)
        return instance.render(**cve_data)


class HackerOneTemplate(BaseTemplate):
    """
    HackerOne-style vulnerability report template.

    HackerOne prefers markdown reports with clear sections,
    detailed reproduction steps, and comprehensive evidence.

    Key differences from other platforms:
    - More detailed technical sections expected
    - Screenshots and videos highly valued
    - CVSS justification required per metric
    - Timeline section appreciated
    """

    TEMPLATE_STRING = HACKERONE_TEMPLATE
    PLATFORM = "hackerone"

    def __init__(self, config: TemplateConfig | None = None):
        super().__init__(config)
        if self.config.platform != "hackerone":
            self.config.platform = "hackerone"

    def get_required_fields(self) -> list[str]:
        base = super().get_required_fields()
        return base + [
            "root_cause", "attack_vector",
            "av", "ac", "pr", "ui", "s", "c", "i", "a",
        ]

    def render_quick(self, cve_id: str, impact: str, steps: str, **kwargs: Any) -> str:
        """
        Quick render with minimal required fields.

        Args:
            cve_id: The CVE identifier
            impact: One-line impact description
            steps: Brief reproduction steps
            **kwargs: Additional template variables

        Returns:
            Rendered report
        """
        return self.render(
            cve_id=cve_id,
            title=f"Vulnerability in {kwargs.get('affected_product', 'Target')} - {cve_id}",
            executive_summary=f"A vulnerability tracked as {cve_id} was identified. {impact}",
            impact_description=impact,
            reproduction_steps=steps,
            **kwargs,
        )


class BugcrowdTemplate(BaseTemplate):
    """
    Bugcrowd-style vulnerability submission template.

    Bugcrowd has a more structured form-based submission but
    markdown attachments are supported and valued.

    Key differences:
    - More concise format preferred
    - Environment section important
    - Business impact emphasis
    - Vulnerability type classification required
    """

    TEMPLATE_STRING = BUGCROWD_TEMPLATE
    PLATFORM = "bugcrowd"

    def __init__(self, config: TemplateConfig | None = None):
        super().__init__(config)
        if self.config.platform != "bugcrowd":
            self.config.platform = "bugcrowd"

    def render_quick(self, cve_id: str, vuln_type: str, impact: str, steps: str, **kwargs: Any) -> str:
        """Quick render for Bugcrowd."""
        return self.render(
            cve_id=cve_id,
            title=f"{vuln_type} via {cve_id}",
            vuln_type=vuln_type,
            executive_summary=f"{cve_id} - {vuln_type}: {impact}",
            vulnerability_description=f"The target is affected by {cve_id}, a known vulnerability.",
            impact_description=impact,
            business_impact=impact,
            reproduction_steps=steps,
            **kwargs,
        )


class InternalAssessmentTemplate(BaseTemplate):
    """
    Internal security assessment report template.

    Formal report format suitable for internal stakeholders,
    compliance teams, and security operations.

    Key features:
    - Classification markings
    - Compliance impact section
    - Detailed remediation timeline
    - Affected assets inventory
    """

    TEMPLATE_STRING = INTERNAL_ASSESSMENT_TEMPLATE
    PLATFORM = "internal"

    def __init__(self, config: TemplateConfig | None = None):
        super().__init__(config)
        if self.config.platform != "internal":
            self.config.platform = "internal"

    def _build_context(self, **kwargs: Any) -> dict[str, Any]:
        context = super()._build_context(**kwargs)
        # Add internal-specific defaults
        context.setdefault("classification", "CONFIDENTIAL")
        context.setdefault("department_owner", "IT Security")
        context.setdefault("report_id", f"SEC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-001")
        context.setdefault("cve_list", [])
        context.setdefault("affected_assets", [])
        context.setdefault("cvss_calculation_details", "")
        context.setdefault("tools_used", "PocMap, Nmap, Burp Suite")
        context.setdefault("immediate_actions", "1. Apply emergency patch\n2. Implement WAF rules\n3. Monitor for exploitation attempts")
        context.setdefault("short_term_actions", "1. Upgrade to fixed version\n2. Conduct vulnerability scan\n3. Review compensating controls")
        context.setdefault("long_term_actions", "1. Implement automated patching\n2. Add vulnerability scanning to CI/CD\n3. Security architecture review")
        context.setdefault("compensating_controls", "WAF virtual patching, network segmentation, enhanced monitoring")
        return context

    def render_multi_cve(self, cve_list: list[dict[str, Any]], **kwargs: Any) -> str:
        """
        Render report with multiple CVEs.

        Args:
            cve_list: List of CVE data dictionaries
            **kwargs: Additional template variables

        Returns:
            Rendered report
        """
        critical_count = sum(1 for c in cve_list if c.get("severity") == "Critical")
        high_count = sum(1 for c in cve_list if c.get("severity") == "High")
        medium_count = sum(1 for c in cve_list if c.get("severity") == "Medium")

        context = self._build_context(**kwargs)
        context["cve_list"] = cve_list
        context["critical_count"] = critical_count
        context["high_count"] = high_count
        context["medium_count"] = medium_count
        context["kev_count"] = sum(1 for c in cve_list if c.get("kev_listed"))

        return render_template(self.TEMPLATE_STRING, context)


class ExecutiveSummaryTemplate(BaseTemplate):
    """
    Executive summary template for non-technical stakeholders.

    Focuses on business impact, risk, and investment required
    rather than technical details.

    Key features:
    - Minimal technical jargon
    - Business risk focus
    - Cost/timeline estimates
    - Clear action items
    """

    TEMPLATE_STRING = EXECUTIVE_SUMMARY_TEMPLATE
    PLATFORM = "executive"

    def __init__(self, config: TemplateConfig | None = None):
        super().__init__(config)
        if self.config.platform != "executive":
            self.config.platform = "executive"

    def _build_context(self, **kwargs: Any) -> dict[str, Any]:
        context = super()._build_context(**kwargs)
        context.setdefault("executive_audience", "C-Suite / Board")
        context.setdefault("classification", "CONFIDENTIAL")
        context.setdefault("tldr", "Security vulnerabilities have been identified that require immediate attention.")
        context.setdefault("bottom_line", "We need to act now to prevent potential security incidents.")
        context.setdefault("critical_count", 0)
        context.setdefault("high_count", 0)
        context.setdefault("medium_count", 0)
        context.setdefault("kev_count", 0)
        context.setdefault("systems_affected", "Unknown")
        context.setdefault("estimated_fix_time", "Unknown")
        context.setdefault("business_impact_level", "High")
        context.setdefault("risk_scenarios", "- Data breach\n- Service disruption\n- Regulatory fines\n- Reputational damage")
        context.setdefault("recommendations", "1. Approve emergency patching budget\n2. Assign dedicated remediation team\n3. Implement continuous vulnerability monitoring")
        context.setdefault("emergency_patch_cost", "$5,000 - $15,000")
        context.setdefault("emergency_patch_timeline", "24-48 hours")
        context.setdefault("waf_cost", "$2,000 - $5,000")
        context.setdefault("waf_timeline", "1-3 days")
        context.setdefault("full_remediation_cost", "$10,000 - $50,000")
        context.setdefault("full_remediation_timeline", "1-4 weeks")
        context.setdefault("next_steps", "1. Schedule emergency meeting\n2. Assign ownership\n3. Approve budget\n4. Begin remediation")
        context.setdefault("researcher_contact", "security-team@company.com")
        return context

    def render_from_cve_list(self, cve_list: list[dict[str, Any]], **kwargs: Any) -> str:
        """
        Render executive summary from a list of CVEs.

        Args:
            cve_list: List of CVE dictionaries with severity, etc.
            **kwargs: Additional context

        Returns:
            Rendered executive summary
        """
        critical = sum(1 for c in cve_list if c.get("severity") == "Critical")
        high = sum(1 for c in cve_list if c.get("severity") == "High")
        medium = sum(1 for c in cve_list if c.get("severity") == "Medium")
        kev = sum(1 for c in cve_list if c.get("kev_listed"))

        systems = len({c.get("target", "") for c in cve_list})

        return self.render(
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            kev_count=kev,
            systems_affected=systems,
            **kwargs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# INTIGRITI TEMPLATE (Additional platform)
# ═══════════════════════════════════════════════════════════════════════════════

INTIGRITI_TEMPLATE = """# Intigriti Submission: {{ title }}

## Finding Summary

**Type:** {{ vuln_type }}
**Severity:** {{ severity }}
**Asset:** {{ target_url }}
**CVE:** {{ cve_id }}
**Researcher:** {{ researcher_handle }}

---

## Description

{{ executive_summary }}

### Vulnerability Details

- **CVE ID:** {{ cve_id }}
- **CVSS Score:** {{ cvss_score }}
- **Affected Component:** {{ affected_product }}
- **Affected Version(s):** {{ affected_versions }}

{{ vulnerability_description }}

---

## Proof of Concept

{{ poc_summary }}

### Reproduction

{{ reproduction_steps }}

{% if poc_code %}
```
{{ poc_code }}
```
{% endif %}

---

## Impact

{{ impact_description }}

---

## Fix Recommendation

{{ remediation_primary }}

---

## References

{{ references }}

---

*Submitted via Intigriti*
*Generated with PocMap Bug Bounty Toolkit*
"""


class IntigritiTemplate(BaseTemplate):
    """Intigriti platform report template."""

    TEMPLATE_STRING = INTIGRITI_TEMPLATE
    PLATFORM = "intigriti"

    def __init__(self, config: TemplateConfig | None = None):
        super().__init__(config)
        if self.config.platform != "intigriti":
            self.config.platform = "intigriti"


# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATE FACTORY AND HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

TEMPLATE_REGISTRY: dict[str, type[BaseTemplate]] = {
    "hackerone": HackerOneTemplate,
    "bugcrowd": BugcrowdTemplate,
    "intigriti": IntigritiTemplate,
    "internal": InternalAssessmentTemplate,
    "executive": ExecutiveSummaryTemplate,
}


def get_template(platform: str, config: TemplateConfig | None = None) -> BaseTemplate:
    """
    Get a template instance by platform name.

    Args:
        platform: One of: hackerone, bugcrowd, intigriti, internal, executive
        config: Optional template configuration

    Returns:
        Template instance for the specified platform

    Raises:
        ValueError: If platform is not supported
    """
    platform = platform.lower()
    if platform not in TEMPLATE_REGISTRY:
        raise ValueError(
            f"Unknown platform: {platform}. "
            f"Supported: {list(TEMPLATE_REGISTRY.keys())}"
        )
    return TEMPLATE_REGISTRY[platform](config=config)


def list_platforms() -> list[str]:
    """List supported platform names."""
    return list(TEMPLATE_REGISTRY.keys())


def render_quick_report(
    platform: str,
    cve_id: str,
    impact: str,
    steps: str,
    **kwargs: Any,
) -> str:
    """
    Quickly render a report with minimal fields.

    Args:
        platform: Target platform name
        cve_id: CVE identifier
        impact: Impact description
        steps: Reproduction steps
        **kwargs: Additional fields

    Returns:
        Rendered report string
    """
    template = get_template(platform)
    if hasattr(template, "render_quick"):
        rendered: str = template.render_quick(cve_id, impact, steps, **kwargs)
        return rendered
    return template.render(
        cve_id=cve_id,
        impact_description=impact,
        reproduction_steps=steps,
        **kwargs,
    )


def auto_render_from_cve(cve_data: dict[str, Any], platform: str = "hackerone", **kwargs: Any) -> str:
    """
    Automatically render a report from CVE data from pocmap.

    Args:
        cve_data: CVE data dictionary or Pydantic model from pocmap services
        platform: Target platform
        **kwargs: Additional template fields to pass through

    Returns:
        Rendered report
    """
    template = get_template(platform)

    # Map pocmap data format to template fields
    # Use _get_value to handle both dicts and Pydantic models
    field_mapping = {
        "id": "cve_id",
        "cve_id": "cve_id",
        "cvss": "cvss_score",
        "cvss3_score": "cvss_score",
        "epss": "epss_score",
        "cwe": "cwe_id",
        "cwes": "cwe_id",
        "description": "vulnerability_description",
        "product": "affected_product",
        "affected_versions": "affected_versions",
        "fixed_version": "fixed_version",
        "severity": "severity",
        "title": "title",
        "references": "references",
        "kev_status": "kev_listed",
    }

    mapped = {}
    for src, dst in field_mapping.items():
        val = _get_value(cve_data, src)
        if val is not None:
            mapped[dst] = val

    # --- Issue 3: Extract scalar CVSS score from dict/model ---
    cvss_score = mapped.get("cvss_score")
    if cvss_score is not None and not isinstance(cvss_score, (int, float)):
        # cvss_score could be a dict, a Pydantic CVSSScore model, or a string
        if isinstance(cvss_score, dict):
            mapped["cvss_score"] = cvss_score.get("base_score", "N/A")
        elif hasattr(cvss_score, "base_score"):
            mapped["cvss_score"] = cvss_score.base_score
        else:
            mapped["cvss_score"] = str(cvss_score)

    # --- Issue 5: EPSS scale 0-100 → 0-1 ---
    epss = mapped.get("epss_score")
    if epss is not None:
        try:
            epss_float = float(epss)
            mapped["epss_score"] = epss_float / 100.0 if epss_float > 1 else epss_float
        except (ValueError, TypeError):
            mapped["epss_score"] = epss

    # --- Normalize kev_listed to a displayable string ---
    kev = mapped.get("kev_listed")
    if isinstance(kev, bool):
        mapped["kev_listed"] = "Yes" if kev else "No"

    # Set defaults
    mapped.setdefault("report_date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    mapped.setdefault("title", f"Vulnerability Report - {mapped.get('cve_id', 'Unknown')}")

    return template.render(**{**mapped, **kwargs})
