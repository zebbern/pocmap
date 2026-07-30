"""OSV.dev client — vulnerability lookups keyed by *package*.

Complements the NVD/CPE path rather than replacing it. The two model different
things, and the difference is not cosmetic:

* NVD files vulnerabilities against a **CPE product** (``f5:nginx``), which is
  what answers "is the nginx we deploy vulnerable". OSV rejects a bare product
  name outright — ``{"package": {"name": "nginx"}}`` returns HTTP 400, because
  ecosystem is mandatory — so it cannot serve :mod:`pocmap.services.product_service`.
* OSV files them against a **package coordinate** (``PyPI/django``,
  ``Maven/org.apache.logging.log4j:log4j-core``), which is what answers "is the
  dependency in this lockfile vulnerable, and which release fixes it". NVD
  carries no package coordinate at all, so that question was previously
  unanswerable here.

Two properties of the data drive the design:

* **Fixed versions are only meaningful scoped to one package.** A single
  advisory covers every package that ships the vulnerable code, and their fix
  streams differ. Log4Shell's ``GHSA-jfh8-c2jp-5v3q`` lists ``2.15.0`` for
  ``org.apache.logging.log4j:log4j-core`` but ``1.9.2`` / ``1.10.8`` for the
  ``org.ops4j.pax.logging`` repackager. Flattening the advisory's ``affected[]``
  therefore reports fixes that do not exist for the package the caller asked
  about, so :func:`fixed_versions` filters by coordinate first.
* **Ecosystem names are case-sensitive.** ``PyPI`` resolves; ``pypi``, ``PYPI``
  and ``Pypi`` all return HTTP 400 ``invalid ecosystem``. Callers type the
  lowercase form constantly, so :func:`normalize_ecosystem` maps common
  spellings onto the canonical ones instead of forwarding a guaranteed 400.

Reference: https://google.github.io/osv.dev/api/ and https://ossf.github.io/osv-schema/
"""

from __future__ import annotations

import logging
import re
from typing import Any

from pocmap.config import OSV_QUERY_URL, OSV_VULN_URL, settings
from pocmap.utils.http import (
    HTTPClient,
    HTTPError,
    OfflineError,
    RateLimitError,
    ValidationError,
)

logger = logging.getLogger(__name__)

# OSV returns at most 3000 entries per page and signals more with a
# ``next_page_token``. Bounded so a pathological package (``Debian:12/linux``
# has >6000) cannot spin forever; anything dropped is logged, never silent.
_MAX_PAGES = 5

# Range kinds that carry real version strings. ``GIT`` events carry commit
# hashes, which are not installable versions and must never be reported as a
# "fixed version" — the CVE-keyed OSV record for Log4Shell has GIT ranges only.
_VERSION_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})

# Canonical ecosystem spellings, keyed by their separator-free lowercase slug.
# Values are verified against the live API; the list is the OSV schema's plus
# the aliases callers actually type (``cargo`` for crates.io, ``golang`` for Go).
_CANONICAL_ECOSYSTEMS: tuple[str, ...] = (
    "AlmaLinux",
    "Alpaquita",
    "Alpine",
    "Android",
    "Azure Linux",
    "BellSoft Hardened Containers",
    "Bioconductor",
    "Bitnami",
    "CRAN",
    "Chainguard",
    "CleanStart",
    "ConanCenter",
    "Debian",
    "Docker Hardened Images",
    "Echo",
    "FreeBSD",
    "GHC",
    "GIT",
    "GitHub Actions",
    "Go",
    "Hackage",
    "Hex",
    "Julia",
    "Kubernetes",
    "Linux",
    "Mageia",
    "Maven",
    "MinimOS",
    "NuGet",
    "OSS-Fuzz",
    "Packagist",
    "Photon OS",
    "Pub",
    "PyPI",
    "Red Hat",
    "Rocky Linux",
    "Root",
    "RubyGems",
    "SUSE",
    "SwiftURL",
    "TuxCare",
    "Ubuntu",
    "VSCode",
    "Wolfi",
    "crates.io",
    "npm",
    "opam",
    "openEuler",
    "openSUSE",
    "vcpkg",
)

# Extra spellings people actually type, mapped onto the canonical names above.
# (The canonical names themselves are added programmatically below.)
_ECOSYSTEM_ALIASES: dict[str, str] = {
    "cargo": "crates.io",
    "crates": "crates.io",
    "rust": "crates.io",
    "golang": "Go",
    "haskell": "Hackage",
    "elixir": "Hex",
    "java": "Maven",
    "node": "npm",
    "nodejs": "npm",
    "dotnet": "NuGet",
    "composer": "Packagist",
    "php": "Packagist",
    "dart": "Pub",
    "flutter": "Pub",
    "python": "PyPI",
    "pip": "PyPI",
    "rhel": "Red Hat",
    "redhat": "Red Hat",
    "rocky": "Rocky Linux",
    "gem": "RubyGems",
    "gems": "RubyGems",
    "ruby": "RubyGems",
    "swift": "SwiftURL",
    "actions": "GitHub Actions",
    "alma": "AlmaLinux",
}

#: Ecosystems worth showing in help text / agent-facing docs, in rough order of
#: how often they are asked for. Not exhaustive — any OSV ecosystem is accepted.
COMMON_ECOSYSTEMS: tuple[str, ...] = (
    "PyPI",
    "npm",
    "Go",
    "Maven",
    "crates.io",
    "RubyGems",
    "Packagist",
    "NuGet",
    "Hex",
    "Pub",
    "Debian",
    "Ubuntu",
    "Alpine",
    "Red Hat",
    "Rocky Linux",
    "SUSE",
    "Bitnami",
)

_SLUG_RE = re.compile(r"[^a-z0-9]+")

# PEP 503: runs of '-', '_' and '.' are equivalent in a package name.
_PKG_SEP_RE = re.compile(r"[-_.]+")

#: Slug -> canonical spelling. Canonical names resolve to themselves, so
#: "Red Hat", "redhat" and "RED HAT" all reach ``Red Hat``.
_ECOSYSTEMS: dict[str, str] = {
    **{_SLUG_RE.sub("", name.lower()): name for name in _CANONICAL_ECOSYSTEMS},
    **_ECOSYSTEM_ALIASES,
}


def normalize_ecosystem(value: str) -> str | None:
    """Map a user-written ecosystem onto OSV's canonical, case-sensitive spelling.

    OSV rejects any other casing with HTTP 400 ``invalid ecosystem``, so a
    lowercase ``pypi`` — which is what people type — would otherwise fail for a
    reason that looks like "unknown package".

    A ``:``-suffixed release qualifier is preserved and only the base name is
    normalized, because OSV treats each distro release as its own ecosystem:
    ``debian:12`` -> ``Debian:12``, ``alpine:v3.19`` -> ``Alpine:v3.19``.

    Args:
        value: Ecosystem as written by the caller.

    Returns:
        The canonical spelling, or ``None`` if the name is not recognized. An
        unrecognized name is *not* an error — OSV grows ecosystems over time, so
        callers should forward it verbatim and let the API decide.

    Example::

        normalize_ecosystem("pypi")        # 'PyPI'
        normalize_ecosystem("debian:12")   # 'Debian:12'
    """
    raw = value.strip()
    if not raw:
        return None
    base, sep, suffix = raw.partition(":")
    canonical = _ECOSYSTEMS.get(_SLUG_RE.sub("", base.lower()))
    if canonical is None:
        return None
    return f"{canonical}{sep}{suffix}" if sep else canonical


def cve_ids(vuln: dict[str, Any]) -> list[str]:
    """Return every CVE identifier an OSV record is known by.

    An OSV entry is keyed by its own id (``GHSA-…``, ``PYSEC-…``, ``RUSTSEC-…``)
    and cross-references CVEs through ``aliases``, so the CVE may be in either
    place. Advisories with no CVE at all are common (RUSTSEC and GHSA both
    publish them), and an empty list here means exactly that.
    """
    found: list[str] = []
    candidates = [vuln.get("id"), *(vuln.get("aliases") or [])]
    for value in candidates:
        if isinstance(value, str) and value.upper().startswith("CVE-"):
            upper = value.upper()
            if upper not in found:
                found.append(upper)
    return found


def _normalize_pkg_name(name: str) -> str:
    """Fold a package name to the key its ecosystem compares by.

    OSV stores the *normalized* name, but the caller types the one in their
    manifest — ``Django`` in a ``requirements.txt``, ``PyYAML`` on PyPI. A raw
    ``!=`` therefore matched nothing and emptied ``fixed_versions``, which the
    caller is told to read as "no fix published": the single most dangerous
    wrong answer this tool can give.

    Case folding plus PEP 503's separator rule (``-``, ``_`` and ``.`` are
    equivalent) covers PyPI and npm, and is harmless for the case-sensitive
    ecosystems: Maven coordinates and Go module paths do not vary by case in
    practice, and a collision would require two artifacts differing only in
    punctuation *within the same advisory*.
    """
    return _PKG_SEP_RE.sub("-", name.strip().lower())


def _matches_package(pkg: dict[str, Any], ecosystem: str, name: str) -> bool:
    """Whether an ``affected[].package`` entry is the coordinate we asked about.

    The ecosystem is compared on its base name so a query for ``Debian:12``
    still matches an advisory filed against ``Debian``, which is how OSV records
    a vulnerability that spans releases.
    """
    if _normalize_pkg_name(str(pkg.get("name", ""))) != _normalize_pkg_name(name):
        return False
    declared = str(pkg.get("ecosystem", ""))
    return declared.partition(":")[0] == ecosystem.partition(":")[0]


def _events_for(
    vuln: dict[str, Any], ecosystem: str, name: str, key: str
) -> list[str]:
    """Collect ``events[].<key>`` values from ranges scoped to one package.

    When the caller named a specific distro release (``Debian:12``), entries for
    that exact release win. Falling straight back to a base-name match would
    union the fix streams of every release the advisory covers and hand a
    Debian 12 user the Debian 11 package version — a real-looking string that
    does not exist for them. The base match is kept only as a fallback, for the
    reverse case: a query for plain ``Ubuntu`` must still reach an entry filed
    under ``Ubuntu:Pro:16.04:LTS``.
    """
    entries = [
        a
        for a in (vuln.get("affected") or [])
        if isinstance(a, dict)
        and isinstance(a.get("package"), dict)
        and _matches_package(a["package"], ecosystem, name)
    ]
    exact = [
        a for a in entries if str(a["package"].get("ecosystem", "")) == ecosystem
    ]
    out: list[str] = []
    for affected in exact or entries:
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict) or rng.get("type") not in _VERSION_RANGE_TYPES:
                continue
            for event in rng.get("events") or []:
                if not isinstance(event, dict):
                    continue
                value = event.get(key)
                # "introduced": "0" means "since the beginning" — a real bound
                # in the schema, but noise in a human-facing version list.
                if isinstance(value, str) and value and value != "0" and value not in out:
                    out.append(value)
    return out


def fixed_versions(vuln: dict[str, Any], ecosystem: str, name: str) -> list[str]:
    """Return the releases that fix *vuln* **for this package coordinate**.

    Scoped deliberately: one advisory covers every package shipping the
    vulnerable code, and their fix streams differ (see the module docstring's
    Log4Shell example). A flat scan over ``affected[]`` reports versions that do
    not exist for the package the caller asked about.

    Multiple values are normal and not a contradiction — a project backports a
    fix to each maintained branch, so log4j-core is fixed in ``2.3.1``,
    ``2.12.2`` *and* ``2.15.0`` depending on the branch in use.

    Returns:
        Fixed versions in the order OSV lists them. Empty when the advisory has
        no fix recorded for this package — which means "no fix published here",
        not "not vulnerable".
    """
    return _events_for(vuln, ecosystem, name, "fixed")


def introduced_versions(vuln: dict[str, Any], ecosystem: str, name: str) -> list[str]:
    """Return the releases that introduced *vuln* for this package coordinate."""
    return _events_for(vuln, ecosystem, name, "introduced")


def _collect_severity(vuln: dict[str, Any]) -> dict[str, str]:
    """Gather CVSS vectors by type from both places OSV puts them.

    ``severity[]`` exists at the top level *and* nested under each
    ``affected[]`` entry, and for some sources (every Bitnami record) the nested
    copy is the only one — reading just the top level loses them entirely.
    Top-level wins on conflict; duplicates within a list are common and
    deduplicated by ``setdefault``.
    """
    by_type: dict[str, str] = {}

    def absorb(entries: Any) -> None:
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            score = entry.get("score")
            kind = str(entry.get("type", ""))
            # A CVSS v2 vector has no "CVSS:" prefix ("AV:N/AC:M/Au:N/..."),
            # and non-CVSS ordinals appear in the same array
            # ({"type": "Ubuntu", "score": "high"}) — so trust the declared
            # type rather than sniffing the string.
            if isinstance(score, str) and score and kind.startswith("CVSS_"):
                by_type.setdefault(kind, score)

    absorb(vuln.get("severity"))
    for affected in vuln.get("affected") or []:
        if isinstance(affected, dict):
            absorb(affected.get("severity"))
    return by_type


def severity_vector(vuln: dict[str, Any]) -> str | None:
    """Return the CVSS vector string OSV carries, preferring the newest version."""
    by_type = _collect_severity(vuln)
    for kind in ("CVSS_V4", "CVSS_V3", "CVSS_V2"):
        if kind in by_type:
            return by_type[kind]
    return next(iter(by_type.values()), None)


def scorable_vector(vuln: dict[str, Any]) -> str | None:
    """Return a CVSS **3.x** vector, the only kind pocmap can score locally.

    :func:`severity_vector` prefers the newest vector for display; this prefers
    the one that yields a number. A 4.0-only advisory returns ``None`` so the
    caller falls back to the publisher's qualitative rating rather than to a
    wrong score (see :mod:`pocmap.utils.cvss`).
    """
    vector = _collect_severity(vuln).get("CVSS_V3")
    return vector if vector and vector.startswith("CVSS:3") else None


def qualitative_severity(vuln: dict[str, Any]) -> str | None:
    """Return the publisher's own severity rating, if it published one.

    Vocabulary differs by source — GitHub advisories say ``MODERATE`` where
    Bitnami says ``Medium`` — so the value is normalized onto the CVSS scale.
    """
    from pocmap.utils.cvss import normalize_qualitative

    raw = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(raw, str) and raw:
        return normalize_qualitative(raw)
    return None


def is_withdrawn(vuln: dict[str, Any]) -> bool:
    """Whether an advisory has been retracted by its publisher.

    ``/v1/query`` already omits withdrawn records, so this only matters for an
    id resolved some other way (an alias hop, a cached list, an SBOM). There is
    no ``rejected`` field — retraction is signalled solely by the presence of a
    ``withdrawn`` timestamp.
    """
    return bool(vuln.get("withdrawn"))


def _explain_bad_request(exc: HTTPError, payload: dict[str, Any]) -> str:
    """Turn OSV's terse 400 into a message that names the likely fix."""
    detail = str(exc)
    package = payload.get("package") or {}
    ecosystem = str(package.get("ecosystem", ""))
    if "invalid ecosystem" in detail:
        canonical = normalize_ecosystem(ecosystem)
        hint = (
            f" Did you mean {canonical!r}?"
            if canonical and canonical != ecosystem
            else " Ecosystem names are case-sensitive; see COMMON_ECOSYSTEMS."
        )
        return f"OSV rejected ecosystem {ecosystem!r}.{hint}"
    if "invalid query" in detail:
        return (
            "OSV rejected the query: a package lookup needs both a name and an "
            f"ecosystem (got name={package.get('name')!r}, ecosystem={ecosystem!r})."
        )
    return f"OSV rejected the request: {detail}"


class OSVClient:
    """Client for the OSV.dev vulnerability database.

    Needs no API key and imposes no per-key quota, which makes it materially
    cheaper to query than NVD (5 requests / 30s unauthenticated).

    Args:
        http_client: Optional HTTP client instance.

    Example::

        with OSVClient() as client:
            vulns = client.query("PyPI", "django", version="3.2.0")
            for v in vulns:
                print(v["id"], fixed_versions(v, "PyPI", "django"))
    """

    def __init__(self, http_client: HTTPClient | None = None) -> None:
        # OSV's query endpoint is a POST whose body *is* the query, so it is a
        # read: retrying it is side-effect free, unlike the webhook POST the
        # default policy is written for.
        self._client = http_client or HTTPClient(
            headers=settings.default_headers,
            retry_methods=("HEAD", "GET", "OPTIONS", "POST"),
        )

    def query(
        self,
        ecosystem: str,
        name: str,
        version: str | None = None,
        max_pages: int = _MAX_PAGES,
    ) -> list[dict[str, Any]]:
        """Return the OSV records affecting a package, optionally at one version.

        Args:
            ecosystem: Canonical OSV ecosystem (``PyPI``, ``npm``, ``Debian:12``).
                Case matters; run it through :func:`normalize_ecosystem` first.
            name: Package name as the ecosystem spells it
                (``org.apache.logging.log4j:log4j-core`` for Maven).
            version: Exact installed version. When given, OSV evaluates the
                affected ranges itself and returns only what actually applies —
                which is more trustworthy than comparing versions client-side,
                because each ecosystem orders versions by its own rules.
            max_pages: Page-follow bound.

        Returns:
            Raw OSV vulnerability records. Empty means "no known
            vulnerabilities" — a valid ecosystem with no data returns HTTP 200
            with an empty list, so this is never a disguised failure.

        Raises:
            OfflineError: Offline mode with no cached response.
            RateLimitError: OSV throttled the request.
            ValidationError: OSV rejected the query (unknown ecosystem).
            HTTPError: Any other upstream failure — never degraded to an empty
                result, since "no vulnerabilities" is a safety claim.
        """
        if not ecosystem.strip() or not name.strip():
            return []

        package: dict[str, Any] = {"name": name, "ecosystem": ecosystem}
        body: dict[str, Any] = {"package": package}
        if version:
            body["version"] = version

        vulns: list[dict[str, Any]] = []
        seen: set[str] = set()
        token: str | None = None
        for page in range(max_pages):
            payload = dict(body)
            if token:
                payload["page_token"] = token
            data = self._post(payload)
            for entry in data.get("vulns") or []:
                if not isinstance(entry, dict):
                    continue
                key = str(entry.get("id", ""))
                if key and key in seen:
                    continue
                if key:
                    seen.add(key)
                vulns.append(entry)
            token = data.get("next_page_token")
            if not isinstance(token, str) or not token:
                return vulns
            if page == max_pages - 1:
                logger.info(
                    "OSV has more results for %s/%s beyond %d pages (%d collected); "
                    "narrow the query with an exact version to see the rest",
                    ecosystem,
                    name,
                    max_pages,
                    len(vulns),
                )
        return vulns

    def get_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        """Fetch one OSV record by id (``CVE-…``, ``GHSA-…``, ``PYSEC-…``).

        Note that a CVE-keyed record usually carries only ``GIT`` ranges — the
        installable fixed versions live on the ecosystem-keyed alias. Use
        :meth:`aliases` to hop across.

        Returns:
            The record, or ``None`` when OSV has no such id.

        Raises:
            OfflineError: Offline mode with no cached response.
            RateLimitError: OSV throttled the request.
        """
        vuln_id = vuln_id.strip()
        if not vuln_id or "/" in vuln_id or "\\" in vuln_id:
            return None
        try:
            data = self._client.get_json(f"{OSV_VULN_URL}/{vuln_id}")
        except (OfflineError, RateLimitError):
            raise
        except HTTPError as exc:
            logger.warning("OSV lookup failed for %s: %s", vuln_id, exc)
            return None
        return data if isinstance(data, dict) else None

    def aliases(self, vuln_id: str) -> list[str]:
        """Return the ids *vuln_id* is cross-referenced with (CVE <-> GHSA)."""
        record = self.get_vuln(vuln_id)
        if record is None:
            return []
        found = record.get("aliases")
        return [a for a in found if isinstance(a, str)] if isinstance(found, list) else []

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST a query body.

        Raises:
            ValidationError: OSV rejected the query itself (HTTP 400) — a bad
                ecosystem name or a malformed body. This must not degrade into
                an empty result: "you spelled PyPI wrong" and "this package is
                clean" are opposite answers, and OSV returns a *200* for the
                latter.
            HTTPError: Any other upstream failure. Also never degraded, because
                an empty result here reads as "this dependency is safe".
        """
        try:
            data = self._client.post_json_cached(OSV_QUERY_URL, payload)
        except (OfflineError, RateLimitError):
            # An offline cache-miss or a throttled upstream must surface as an
            # upstream failure, never as "this package has no vulnerabilities".
            raise
        except HTTPError as exc:
            if exc.status_code == 400:
                raise ValidationError(_explain_bad_request(exc, payload)) from exc
            # Do NOT degrade to an empty result. Elsewhere in pocmap an empty
            # list means "nothing found"; here it means "this dependency is
            # safe to ship", and answering that because OSV was unreachable is
            # the worst failure this tool has. Let it surface as an upstream
            # error instead.
            raise
        if not isinstance(data, dict):
            raise HTTPError(f"OSV returned a non-object response for {OSV_QUERY_URL}")
        return data

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> OSVClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
