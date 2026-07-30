"""Pydantic data models for the PocMap package.

All data structures used throughout the package are strictly defined here
using Pydantic models. These models provide:
    - Runtime validation and serialization
    - JSON Schema generation for AI agent consumption
    - Type-safe data flow between services

To export JSON schemas for AI agent integration::

    from pocmap.models import export_schemas
    export_schemas("./schemas/")
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ``typing.Self`` only exists on Python 3.11+; fall back to typing_extensions
# (always present as a pydantic dependency) so the package imports on 3.10.
if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from pocmap.utils import validators as _validators

# ---------------------------------------------------------------------------
# Validation constants and helpers
# ---------------------------------------------------------------------------
#
# CVE-ID validation — the regex, the length bound, and ``validate_cve_id`` —
# lives in ``pocmap.utils.validators``, the single source of truth used by
# every service and the CLI. The constant and function are re-exported here
# (as genuine module-level bindings) so existing importers of ``pocmap.models``
# keep working while the rules stay defined in exactly one place.
MAX_CVE_ID_LENGTH = _validators.MAX_CVE_ID_LENGTH
validate_cve_id = _validators.validate_cve_id

MAX_CVE_BULK: int = 100  # Prevent DoS on bulk operations


def validate_cve_count(count: int) -> None:
    """Validate that the number of CVEs to process is within limits.

    Args:
        count: The number of CVEs requested.

    Raises:
        ValueError: If the count exceeds the maximum allowed.
    """
    if count > MAX_CVE_BULK:
        raise ValueError(f"Too many CVEs (max {MAX_CVE_BULK}), got {count}")


def _coerce_optional_float(value: Any) -> float | None:
    """Coerce a raw API value into an optional float.

    Sentinel non-values (``None``, ``"N/A"``, ``""``) and unparseable inputs
    both collapse to ``None``; anything ``float()`` accepts is returned as-is.
    """
    if value is None or value == "N/A" or value == "":
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CVSSVersion(str, Enum):
    """Supported CVSS version identifiers."""

    V2_0 = "2.0"
    V3_0 = "3.0"
    V3_1 = "3.1"
    V4_0 = "4.0"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """CVSS severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class CVEState(str, Enum):
    """Publication states for a CVE identifier."""

    PUBLISHED = "PUBLISHED"
    RESERVED = "RESERVED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class ExploitSource(str, Enum):
    """Known sources for exploit code."""

    GITHUB = "github"
    EXPLOITDB = "exploitdb"
    METASPLOIT = "metasploit"
    NUCLEI = "nuclei"
    TRICKEST = "trickest"
    NOMI_SEC = "nomi-sec"
    OTHER = "other"


class LabPlatform(str, Enum):
    """Platforms hosting CTF/lab environments."""

    HACKTHEBOX = "hackthebox"
    TRYHACKME = "tryhackme"
    VULHUB = "vulhub"
    OTHER = "other"


class BugBountySource(str, Enum):
    """Sources for bug bounty write-ups."""

    HACKERONE = "hackerone"
    PENTESTERLAND = "pentesterland"
    BUGBOUNTY_HUNTING = "bugbounty_hunting"
    OTHER = "other"


class MSFRank(str, Enum):
    """Metasploit exploit reliability ranking."""

    EXCELLENT = "excellent"
    GREAT = "great"
    GOOD = "good"
    NORMAL = "normal"
    AVERAGE = "average"
    LOW = "low"
    MANUAL = "manual"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class VersionConstraint(BaseModel):
    """Parsed version constraint for matching against CVE-affected versions.

    Handles exact versions, wildcards (e.g., ``2.x``), and range operators
    (e.g., ``>= 2.0``).

    Attributes:
        major: Major version number, or ``"x"`` for wildcard.
        minor: Minor version number, or ``"x"`` for wildcard.
        patch: Patch version number, or ``"x"`` for wildcard.
        range_op: Comparison operator (``">="``, ``"<="``, ``">"``, ``"<"``, ``"="``).
        raw: The original version string.
        is_wildcard: Whether any component is a wildcard.
    """

    major: int | str | None = Field(
        default=None, description="Major version (int or 'x' for wildcard)"
    )
    minor: int | str | None = Field(
        default=None, description="Minor version (int or 'x' for wildcard)"
    )
    patch: int | str | None = Field(
        default=None, description="Patch version (int or 'x' for wildcard)"
    )
    range_op: str | None = Field(
        default=None, description='Range operator: >=, <=, >, <, ='
    )
    raw: str = Field(default="", description="Original version string")
    is_wildcard: bool = Field(default=False, description="Whether the version contains wildcards")


class ProductDiscoveryResult(BaseModel):
    """Result of a product discovery query.

    CVEs are grouped into three confidence tiers based on how well they
    match the requested product and version:

    - **confirmed_affected**: Vendor AND product match AND version constraint is met.
    - **possibly_affected**: Vendor OR product matches but version info is unclear.
    - **not_enough_data**: CVE has no vendor/product info to determine relevance.

    Attributes:
        query: Original search query string.
        normalized_vendor: Canonical vendor name after normalization.
        normalized_product: Canonical product name after normalization.
        version_constraint: Parsed version constraint (if provided).
        confirmed_affected: CVEs confirmed to affect this product/version.
        possibly_affected: CVEs possibly affecting this product.
        not_enough_data: CVEs with insufficient info to categorize.
        total_found: Total number of CVEs analyzed.
        search_sources: List of data sources queried.
    """

    query: str = Field(description="Original search query")
    normalized_vendor: str | None = Field(default=None, description="Canonical vendor name")
    normalized_product: str | None = Field(default=None, description="Canonical product name")
    version_constraint: VersionConstraint | None = Field(
        default=None, description="Parsed version constraint"
    )
    confirmed_affected: list[CVEInfo] = Field(
        default_factory=list, description="CVEs confirmed to affect this product/version"
    )
    possibly_affected: list[CVEInfo] = Field(
        default_factory=list, description="CVEs possibly affecting this product (vendor match, version unclear)"
    )
    not_enough_data: list[CVEInfo] = Field(
        default_factory=list, description="CVEs with insufficient product/version info"
    )
    total_found: int = Field(default=0, description="Total CVEs analyzed")
    search_sources: list[str] = Field(default_factory=list, description="Data sources queried")
    matched_cpes: list[str] = Field(
        default_factory=list,
        description=(
            "Canonical vendor:product CPE prefixes the query resolved to. "
            "Empty when the product could not be resolved and the noisier "
            "keyword search was used instead (see ``search_sources``)."
        ),
    )


class PackageVulnerability(BaseModel):
    """A vulnerability affecting one *package* coordinate, as OSV files it.

    Distinct from :class:`CVEInfo`, which is keyed on a CPE product. The unit
    here is a dependency — ``PyPI/django``, ``Maven/org.apache…:log4j-core`` —
    so this model carries the one thing a CPE record cannot: the releases that
    fix the issue.

    ``fixed_versions`` is scoped to the queried package. One advisory covers
    every package that ships the vulnerable code and their fix streams differ,
    so a version listed here is a real upgrade target for *this* package only.
    Several entries are normal rather than contradictory — a project backports
    a fix to each maintained branch.

    An empty ``fixed_versions`` means no fix is published for this package, not
    that it is unaffected.

    Attributes:
        id: OSV identifier (``GHSA-…``, ``PYSEC-…``, ``RUSTSEC-…``, ``CVE-…``).
        aliases: Other identifiers the advisory is cross-referenced under.
        cve_ids: CVE identifiers among ``id``/``aliases``; empty is common, as
            many ecosystem advisories never receive one.
        summary: One-line advisory title.
        details: Full advisory prose, when the caller asked for it.
        severity: Qualitative rating, derived from the CVSS vector when one is
            scoreable and otherwise from the publisher's own label.
        cvss_score: CVSS 3.x base score computed from ``cvss_vector``. ``None``
            for a 4.0-only advisory, which pocmap does not score locally.
        cvss_vector: The CVSS vector string as published.
        fixed_versions: Releases fixing this issue *for this package*.
        introduced_versions: Releases that introduced it.
        epss: EPSS exploitation probability (0-100), when a CVE alias exists.
        kev_status: Whether a CVE alias is in the CISA KEV catalog.
        withdrawn: RFC3339 timestamp if the advisory was retracted.
        published: Publication timestamp.
        modified: Last-modified timestamp.
        url: Canonical OSV page for the advisory.
    """

    id: str = Field(..., description="OSV advisory identifier")
    aliases: list[str] = Field(default_factory=list, description="Cross-referenced identifiers")
    cve_ids: list[str] = Field(default_factory=list, description="CVE identifiers, if any")
    summary: str | None = Field(default=None, description="One-line advisory title")
    details: str | None = Field(default=None, description="Full advisory text")
    severity: Severity = Field(default=Severity.UNKNOWN, description="Qualitative severity")
    cvss_score: float | None = Field(
        default=None, ge=0.0, le=10.0, description="CVSS 3.x base score, computed from the vector"
    )
    cvss_vector: str | None = Field(default=None, description="Published CVSS vector string")
    fixed_versions: list[str] = Field(
        default_factory=list, description="Releases that fix this issue for the queried package"
    )
    introduced_versions: list[str] = Field(
        default_factory=list, description="Releases that introduced this issue"
    )
    epss: float | None = Field(
        default=None, ge=0.0, le=100.0, description="EPSS exploitation probability (0-100)"
    )
    kev_status: bool = Field(default=False, description="Listed in the CISA KEV catalog")
    withdrawn: str | None = Field(default=None, description="Retraction timestamp, if withdrawn")
    published: str | None = Field(default=None, description="Publication timestamp")
    modified: str | None = Field(default=None, description="Last-modified timestamp")
    url: str | None = Field(default=None, description="Canonical OSV advisory URL")

    @field_validator("epss", mode="before")
    @classmethod
    def _coerce_pkg_epss(cls, value: Any) -> float | None:
        """Accept a string or numeric EPSS from upstream."""
        return _coerce_optional_float(value)

    @property
    def has_fix(self) -> bool:
        """Whether at least one fixed release is published for this package."""
        return bool(self.fixed_versions)


class PackageDiscoveryResult(BaseModel):
    """Result of a package vulnerability query.

    Attributes:
        ecosystem: Canonical OSV ecosystem the query resolved to.
        package: Package name as the ecosystem spells it.
        version: Installed version the query was evaluated against, if given.
        vulnerabilities: Matching advisories, most severe first.
        total_found: How many advisories were **found** — not how many are in
            ``vulnerabilities``, which ``limit`` may have truncated.
        returned: Length of ``vulnerabilities``.
        truncated: Whether ``limit`` dropped any advisory from the list.
        fixable_count: How many of the *returned* advisories have a fixed release.
        unfixed_count: How many of the *returned* advisories have no published fix.
        search_sources: Data sources that actually contributed. A source that
            failed to load is omitted, so its absence means "unavailable" rather
            than "found nothing".
    """

    ecosystem: str = Field(description="Canonical OSV ecosystem")
    package: str = Field(description="Package name")
    version: str | None = Field(default=None, description="Version the query was evaluated at")
    vulnerabilities: list[PackageVulnerability] = Field(
        default_factory=list, description="Matching advisories, most severe first"
    )
    total_found: int = Field(default=0, description="Advisories found (before any limit)")
    returned: int = Field(default=0, description="Advisories in this response")
    truncated: bool = Field(default=False, description="Whether a limit dropped advisories")
    fixable_count: int = Field(default=0, description="Returned advisories with a published fix")
    unfixed_count: int = Field(default=0, description="Returned advisories with no published fix")
    search_sources: list[str] = Field(default_factory=list, description="Data sources queried")


class CVSSScore(BaseModel):
    """CVSS scoring information for a vulnerability.

    Attributes:
        version: CVSS specification version (e.g., "3.1").
        base_score: Numeric base score (0.0 -- 10.0).
        severity: Human-readable severity level.
        vector_string: Compressed CVSS vector string.
    """

    version: CVSSVersion = Field(default=CVSSVersion.UNKNOWN, description="CVSS version")
    base_score: float | None = Field(
        default=None, ge=0.0, le=10.0, description="CVSS base score"
    )
    severity: Severity = Field(default=Severity.UNKNOWN, description="Severity level")
    vector_string: str | None = Field(
        default=None, description="CVSS vector string"
    )

    @field_validator("base_score", mode="before")
    @classmethod
    def _coerce_base_score(cls, value: Any) -> float | None:
        return _coerce_optional_float(value)

    @classmethod
    def from_raw(cls, version: str, base_score: Any, severity: str, vector_string: Any) -> Self:
        """Create a CVSSScore from raw API values with coercion."""
        v_map = {
            "2.0": CVSSVersion.V2_0, "3.0": CVSSVersion.V3_0,
            "3.1": CVSSVersion.V3_1, "4.0": CVSSVersion.V4_0,
        }
        s_map = {
            "LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM,
            "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL,
        }
        return cls(
            version=v_map.get(str(version), CVSSVersion.UNKNOWN),
            base_score=base_score if base_score not in (None, "N/A", "") else None,
            severity=s_map.get(str(severity).upper(), Severity.UNKNOWN),
            vector_string=vector_string if vector_string not in (None, "N/A", "") else None,
        )


class ATTACKMappingType(str, Enum):
    """How a CVE relates to an ATT&CK technique.

    The distinction is the point: ``exploitation_technique`` is *how the CVE is
    exploited*, while the impact types are *what the attacker achieves next*.
    A detection engineer wants the first; a risk assessment wants the others.
    """

    EXPLOITATION = "exploitation_technique"
    PRIMARY_IMPACT = "primary_impact"
    SECONDARY_IMPACT = "secondary_impact"
    UNKNOWN = "unknown"


class ATTACKTechnique(BaseModel):
    """A MITRE ATT&CK technique a CVE has been mapped to.

    Attributes:
        technique_id: ATT&CK technique ID (e.g. ``T1190``, ``T1505.003``).
        name: Human-readable technique name.
        mapping_type: Whether this is the exploitation technique or an impact.
        comment: The curator's explanation of why the CVE maps here.
        url: Canonical ATT&CK page for the technique.
        references: Supporting references recorded with the mapping.
    """

    technique_id: str = Field(..., description="ATT&CK technique ID")
    name: str = Field(default="", description="Technique name")
    mapping_type: ATTACKMappingType = Field(
        default=ATTACKMappingType.UNKNOWN, description="Exploitation vs impact"
    )
    comment: str | None = Field(default=None, description="Why this CVE maps here")
    url: str = Field(default="", description="ATT&CK technique page")
    references: list[str] = Field(default_factory=list, description="Supporting references")

    @classmethod
    def from_ctid(cls, obj: dict[str, Any]) -> Self:
        """Build from a CTID ``mapping_objects`` entry."""
        tid = str(obj.get("attack_object_id") or "").strip()
        # Sub-techniques live under their parent: T1505.003 -> /T1505/003
        path = tid.replace(".", "/")
        raw_type = str(obj.get("mapping_type") or "").strip()
        try:
            mapping_type = ATTACKMappingType(raw_type)
        except ValueError:
            mapping_type = ATTACKMappingType.UNKNOWN
        refs = obj.get("references")
        return cls(
            technique_id=tid,
            name=str(obj.get("attack_object_name") or ""),
            mapping_type=mapping_type,
            comment=obj.get("comments") or None,
            url=f"https://attack.mitre.org/techniques/{path}/" if tid else "",
            references=[r for r in (refs or []) if isinstance(r, str)],
        )


class CPEInfo(BaseModel):
    """Common Platform Enumeration (CPE) identifier.

    Attributes:
        cpe_string: Full CPE 2.3 URI (e.g., ``cpe:2.3:o:microsoft:windows_10:1607``).
        vendor: Software/hardware vendor name.
        product: Product name.
        version: Product version string.
    """

    cpe_string: str = Field(..., description="Full CPE 2.3 string")
    vendor: str | None = Field(default=None, description="Vendor name")
    product: str | None = Field(default=None, description="Product name")
    version: str | None = Field(default=None, description="Product version")

    @classmethod
    def parse(cls, cpe_string: str) -> Self:
        """Parse a CPE 2.3 string into components."""
        parts = cpe_string.split(":")
        if len(parts) >= 6:
            return cls(
                cpe_string=cpe_string,
                vendor=parts[3] if parts[3] else None,
                product=parts[4] if parts[4] else None,
                version=parts[5] if parts[5] else None,
            )
        return cls(cpe_string=cpe_string)


class AffectedProduct(BaseModel):
    """One ``(vendor, product)`` pair a CVE is recorded against.

    A single CVE routinely names several: the vulnerable component plus every
    distribution that shipped it (e.g. ``f5:nginx`` alongside
    ``fedoraproject:fedora``). Matching must consider all of them — collapsing
    to a single pair silently drops the component the CVE is actually about.

    Attributes:
        vendor: Vendor name as it appears in the CPE (already lowercased by NVD).
        product: Product name as it appears in the CPE.
    """

    vendor: str = Field(..., description="Vendor name from the CPE")
    product: str = Field(..., description="Product name from the CPE")


class CPEMatch(BaseModel):
    """A CPE applicability statement, including its version bounds.

    Modern NVD entries express affected version *ranges* out-of-band: the CPE
    ``criteria`` carries ``*`` in the version field and the real range lives in
    the ``versionStart*`` / ``versionEnd*`` attributes. Reading only the literal
    version field therefore matches everything.

    Attributes:
        criteria: The CPE 2.3 string.
        version_start_including: Inclusive lower bound, if any.
        version_start_excluding: Exclusive lower bound, if any.
        version_end_including: Inclusive upper bound, if any.
        version_end_excluding: Exclusive upper bound, if any.
        vulnerable: Whether NVD marks this CPE as vulnerable (vs. merely a platform).
    """

    criteria: str = Field(..., description="CPE 2.3 string")
    version_start_including: str | None = Field(
        default=None, description="Inclusive lower version bound"
    )
    version_start_excluding: str | None = Field(
        default=None, description="Exclusive lower version bound"
    )
    version_end_including: str | None = Field(
        default=None, description="Inclusive upper version bound"
    )
    version_end_excluding: str | None = Field(
        default=None, description="Exclusive upper version bound"
    )
    vulnerable: bool = Field(default=True, description="Whether NVD marks this CPE vulnerable")

    @classmethod
    def from_nvd(cls, match: dict[str, Any]) -> Self:
        """Build from a raw NVD ``cpeMatch`` object."""
        return cls(
            criteria=match.get("criteria", ""),
            version_start_including=match.get("versionStartIncluding"),
            version_start_excluding=match.get("versionStartExcluding"),
            version_end_including=match.get("versionEndIncluding"),
            version_end_excluding=match.get("versionEndExcluding"),
            vulnerable=bool(match.get("vulnerable", True)),
        )

    @property
    def has_range(self) -> bool:
        """Whether this match carries any out-of-band version bound."""
        return any(
            (
                self.version_start_including,
                self.version_start_excluding,
                self.version_end_including,
                self.version_end_excluding,
            )
        )


class Exploit(BaseModel):
    """A single exploit / PoC entry.

    Attributes:
        source: Where the exploit was found.
        url: Direct URL to the exploit code or repository.
        title: Human-readable title or description.
        language: Primary programming language (if known).
        stars: GitHub star count (if applicable).
        forks: GitHub fork count (if applicable).
        rank: Metasploit exploit rank (if applicable).
    """

    source: ExploitSource = Field(..., description="Exploit source")
    url: str = Field(..., description="URL to exploit")
    title: str | None = Field(default=None, description="Exploit title")
    language: str | None = Field(default=None, description="Programming language")
    stars: int | None = Field(default=None, ge=0, description="GitHub stars")
    forks: int | None = Field(default=None, ge=0, description="GitHub forks")
    rank: MSFRank | None = Field(default=None, description="Metasploit rank")
    command: str | None = Field(
        default=None,
        description="CLI command to run the exploit (e.g., msfconsole command)",
    )

    @classmethod
    def from_github_repo(cls, repo_data: dict[str, Any]) -> Self:
        """Create an Exploit from a GitHub API repository response."""
        return cls(
            source=ExploitSource.GITHUB,
            url=repo_data.get("html_url", ""),
            title=repo_data.get("description") or "N/A",
            language=repo_data.get("language") or "N/A",
            stars=repo_data.get("stargazers_count", 0) or 0,
            forks=repo_data.get("forks_count", 0) or 0,
        )

    @classmethod
    def from_exploitdb(cls, exploit_id: str, file_path: str) -> Self:
        """Create an Exploit from an ExploitDB entry."""
        return cls(
            source=ExploitSource.EXPLOITDB,
            url=f"https://www.exploit-db.com/exploits/{exploit_id}",
            title=file_path,
            command=f"searchsploit -m {exploit_id}",
        )

    @classmethod
    def from_metasploit(cls, fullname: str, rank: str) -> Self:
        """Create an Exploit from a Metasploit module entry."""
        rank_map = {
            "600": MSFRank.EXCELLENT, "500": MSFRank.GREAT, "400": MSFRank.GOOD,
            "300": MSFRank.NORMAL, "200": MSFRank.AVERAGE, "100": MSFRank.LOW,
        }
        return cls(
            source=ExploitSource.METASPLOIT,
            url=f"https://www.rapid7.com/db/modules/{fullname}",
            title=fullname,
            rank=rank_map.get(str(rank), MSFRank.UNKNOWN),
            command=f"msfconsole -q -x 'use {fullname}'",
        )

    @classmethod
    def from_nuclei(cls, template_path: str, url: str) -> Self:
        """Create an Exploit from a Nuclei template entry."""
        return cls(
            source=ExploitSource.NUCLEI,
            url=url,
            title=template_path or "Nuclei template",
            command=f"nuclei -t {template_path} [-u <target>]" if template_path else None,
        )


class LabEnvironment(BaseModel):
    """A CTF lab or pre-built vulnerable Docker environment.

    Attributes:
        platform: Hosting platform (HackTheBox, TryHackMe, Vulhub).
        name: Room/machine/environment name.
        url: Direct URL to access the lab.
        setup_instructions: Step-by-step setup guide (for Vulhub).
    """

    platform: LabPlatform = Field(..., description="Lab platform")
    name: str | None = Field(default=None, description="Lab name")
    url: str = Field(..., description="Lab URL")
    setup_instructions: str | None = Field(
        default=None, description="Setup instructions for local environments"
    )


class BugBountyReport(BaseModel):
    """A bug bounty write-up or disclosure report.

    Attributes:
        source: Platform where the report was published.
        url: Direct URL to the report.
        has_poc: Whether the report includes a PoC demonstration.
        title: Report title.
    """

    source: BugBountySource = Field(..., description="Report source")
    url: str = Field(..., description="Report URL")
    has_poc: bool | None = Field(default=None, description="Whether a PoC is included")
    title: str | None = Field(default=None, description="Report title")


class CVEInfo(BaseModel):
    """Comprehensive CVE (Common Vulnerabilities and Exposures) record.

    Attributes:
        id: The CVE identifier (e.g., ``CVE-2021-44228``).
        description: Human-readable vulnerability description.
        cvss: CVSS scoring information.
        epss: Exploit Prediction Scoring System score (0.0 -- 100.0).
        kev_status: Whether the CVE is in CISA's Known Exploited Vulnerabilities catalog.
        cwes: List of associated CWE (Common Weakness Enumeration) identifiers.
        references: Dictionary of reference names to URLs.
        vendor: Affected vendor name.
        product: Affected product name.
        publication_date: Date the CVE was published.
        state: Current publication state.
        ransomware_usage: Whether the CVE is known to be used in ransomware campaigns.
    """

    id: str = Field(..., description="CVE identifier", pattern=r"^CVE-\d{4}-\d+$")
    description: str | None = Field(default=None, description="Vulnerability description")
    cvss: CVSSScore | None = Field(default=None, description="CVSS score information")
    epss: float | None = Field(
        default=None, ge=0.0, le=100.0, description="EPSS score (0-100)"
    )
    kev_status: bool = Field(default=False, description="CISA KEV status")
    cwes: list[str] = Field(default_factory=list, description="Associated CWEs")
    references: dict[str, str] = Field(default_factory=dict, description="Reference URLs")
    vendor: str | None = Field(default=None, description="Vendor name")
    product: str | None = Field(default=None, description="Product name")
    publication_date: str | None = Field(default=None, description="Publication date")
    state: CVEState = Field(default=CVEState.UNKNOWN, description="CVE state")
    ransomware_usage: str | None = Field(
        default=None, description="Ransomware campaign usage status"
    )
    rejected_reason: str | None = Field(
        default=None, description="Reason for rejection (if state is REJECTED)"
    )
    affected_cpes: list[str] = Field(
        default_factory=list, description="Affected CPE 2.3 strings extracted from NVD data"
    )
    affected_products: list[AffectedProduct] = Field(
        default_factory=list,
        description=(
            "Every (vendor, product) pair the CVE is recorded against. "
            "``vendor``/``product`` above are the first of these, kept for compatibility."
        ),
    )
    cpe_matches: list[CPEMatch] = Field(
        default_factory=list,
        description="Full CPE applicability statements, including version bounds",
    )

    @field_validator("epss", mode="before")
    @classmethod
    def _coerce_epss(cls, value: Any) -> float | None:
        return _coerce_optional_float(value)

    @classmethod
    def from_raw_dict(cls, data: dict[str, Any]) -> Self:
        """Coerce a raw dictionary (from legacy code) into a typed CVEInfo."""
        cvss = CVSSScore.from_raw(
            version=data.get("cvss_version", "unknown"),
            base_score=data.get("base_score"),
            severity=data.get("severity", "UNKNOWN"),
            vector_string=data.get("vector_string"),
        )
        epss_raw = data.get("epss") or data.get("epss_score")
        state_raw = str(data.get("state", "UNKNOWN")).upper()
        cwes_raw = data.get("cwe") or data.get("cwes") or []
        if isinstance(cwes_raw, str):
            cwes_raw = [c.strip() for c in cwes_raw.split(",") if c.strip()]

        try:
            state = CVEState(state_raw)
        except ValueError:
            state = CVEState.UNKNOWN

        return cls(
            id=data.get("cve_id", "CVE-0000-00000"),
            description=data.get("description"),
            cvss=cvss,
            epss=epss_raw,
            kev_status=str(data.get("kev", "No")).lower() in ("yes", "true"),
            cwes=cwes_raw,
            references=data.get("references", {}),
            vendor=data.get("vendor") or "N/A",
            product=data.get("affected_product") or "N/A",
            publication_date=data.get("publication_date") or "N/A",
            state=state,
            ransomware_usage=data.get("ransomware_usage"),
            rejected_reason=data.get("rejectedReasons") if state_raw == "REJECTED" else None,
        )


class RecentExploitResult(BaseModel):
    """Result of a recent exploit discovery query.

    Combines CVE information with PoC discovery status and metadata
    about when the result was retrieved.

    Attributes:
        cve_info: Core CVE metadata and scoring.
        has_poc: Whether at least one PoC/exploit was found.
        poc_sources: List of sources where PoCs were discovered.
        discovered_at: Timestamp when the result was discovered.
    """

    cve_info: CVEInfo = Field(..., description="CVE information")
    has_poc: bool = Field(default=False, description="Whether a PoC is available")
    poc_sources: list[ExploitSource] = Field(default_factory=list, description="PoC sources found")
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None), description="Discovery timestamp")


class ReportEntry(BaseModel):
    """A complete report entry for a single CVE.

    This aggregates all discovered information about a CVE including
    exploit code, lab environments, and bug bounty reports.

    Attributes:
        cve_info: Core CVE metadata and scoring.
        exploits: List of discovered exploit code sources.
        labs: List of available lab/CTF environments.
        bb_reports: List of bug bounty write-ups.
        generated_at: Timestamp when the report was generated.
    """

    cve_info: CVEInfo = Field(..., description="CVE information")
    exploits: list[Exploit] = Field(default_factory=list, description="Discovered exploits")
    labs: list[LabEnvironment] = Field(default_factory=list, description="Lab environments")
    bb_reports: list[BugBountyReport] = Field(
        default_factory=list, description="Bug bounty reports"
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None), description="Report generation timestamp"
    )

    def to_json(self, indent: int = 2) -> str:
        """Serialize the report entry to a JSON string."""
        return self.model_dump_json(indent=indent)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report entry to a plain dictionary."""
        return self.model_dump(mode="json")


class MultiReport(BaseModel):
    """A collection of report entries for multiple CVEs.

    Attributes:
        entries: Mapping of CVE ID to its report entry.
        generated_at: Timestamp when the report was generated.
    """

    entries: dict[str, ReportEntry] = Field(default_factory=dict, description="CVE reports")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None), description="Report generation timestamp"
    )

    def to_json(self, indent: int = 2) -> str:
        """Serialize the multi-report to a JSON string."""
        return self.model_dump_json(indent=indent)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the multi-report to a plain dictionary."""
        return self.model_dump(mode="json")


# ---------------------------------------------------------------------------
# JSON Schema Export
# ---------------------------------------------------------------------------

def export_schemas(output_dir: str | Path) -> list[Path]:
    """Export JSON schemas for all primary models to the given directory.

    This is useful for AI agent integration, allowing agents to understand
    the exact structure of data returned by the package's APIs.

    Args:
        output_dir: Directory path where schema JSON files will be written.

    Returns:
        List of paths to the written schema files.

    Example::

        from pocmap.models import export_schemas
        paths = export_schemas("./schemas")
        print(paths)
        # [Path('./schemas/CVSSScore.json'), Path('./schemas/CVEInfo.json'), ...]
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    models: list[type[BaseModel]] = [
        CVSSScore,
        CVEInfo,
        Exploit,
        LabEnvironment,
        BugBountyReport,
        CPEInfo,
        RecentExploitResult,
        ReportEntry,
        MultiReport,
        VersionConstraint,
        ProductDiscoveryResult,
        PackageVulnerability,
        PackageDiscoveryResult,
    ]

    written: list[Path] = []
    for model in models:
        schema = model.model_json_schema()
        path = out / f"{model.__name__}.json"
        path.write_text(json.dumps(schema, indent=2), encoding="utf-8")
        written.append(path)

    return written
