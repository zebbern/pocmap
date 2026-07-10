"""
Bug Bounty Scope Manager

Tools for parsing, tracking, and managing bug bounty program scope.
Matches CVEs to in-scope assets and monitors scope changes.

Integration:
    - Uses pocmap.services.cve_service for CVE lookups
    - pocmap.services.exploit_service for exploit availability
    - pocmap.bugbounty.prioritization for CVE scoring

Example:
    from pocmap.bugbounty.scope_manager import ScopeManager

    scope = ScopeManager()
    scope.add_program("hackerone", "example", ["*.example.com"], ["*.internal.example.com"])
    scope.parse_scope_file("scope.txt")
    matches = scope.match_cves_to_scope(cve_list)
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pocmap.utils.compat import get_value as _get_value


class AssetType(Enum):
    """Types of assets in bug bounty scope."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    WILDCARD = "wildcard"
    IP_RANGE = "ip_range"
    MOBILE_APP = "mobile_app"
    API = "api"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"
    CLOUD = "cloud"
    OTHER = "other"


class AssetStatus(Enum):
    """Status of an asset in scope."""
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    CONDITIONAL = "conditional"  # e.g., "test in staging only"
    PENDING = "pending"
    CHANGED = "changed"  # Recently modified


@dataclass
class Asset:
    """
    A single asset in a bug bounty program scope.

    Attributes:
        value: The asset identifier (domain, IP, wildcard pattern, etc.)
        asset_type: Type of asset
        status: In-scope, out-of-scope, or conditional
        program: Bug bounty program name
        platform: Platform (hackerone, bugcrowd, etc.)
        notes: Additional notes about this asset
        added_date: When this asset was added to scope
        cve_matches: CVEs that affect this asset
        tech_stack: Identified technologies on this asset
    """
    value: str
    asset_type: AssetType = AssetType.DOMAIN
    status: AssetStatus = AssetStatus.IN_SCOPE
    program: str = ""
    platform: str = ""
    notes: str = ""
    added_date: str = ""
    cve_matches: list[dict[str, Any]] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "asset_type": self.asset_type.value,
            "status": self.status.value,
            "program": self.program,
            "platform": self.platform,
            "notes": self.notes,
            "added_date": self.added_date,
            "cve_matches": self.cve_matches,
            "tech_stack": self.tech_stack,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Asset:
        return cls(
            value=data["value"],
            asset_type=AssetType(data.get("asset_type", "domain")),
            status=AssetStatus(data.get("status", "in_scope")),
            program=data.get("program", ""),
            platform=data.get("platform", ""),
            notes=data.get("notes", ""),
            added_date=data.get("added_date", ""),
            cve_matches=data.get("cve_matches", []),
            tech_stack=data.get("tech_stack", []),
        )

    def matches_domain(self, domain: str) -> bool:
        """Check if a domain matches this asset (supports wildcards)."""
        if self.asset_type == AssetType.WILDCARD:
            pattern = self.value.replace("*.", "*")
            return fnmatch.fnmatch(domain, pattern) or fnmatch.fnmatch(domain, f"*.{self.value.lstrip('*.')}")
        return self.value.lower() == domain.lower()


class ScopeParser:
    """
    Parser for bug bounty scope definitions from various sources.

    Supports parsing from:
    - Plain text files (line-separated)
    - HackerOne scope exports
    - Bugcrowd scope pages
    - Custom JSON formats
    """

    # Regex patterns for asset type detection
    IP_PATTERN = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
    )
    IP_RANGE_PATTERN = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}\s*-\s*(\d{1,3}\.){3}\d{1,3}$"
    )
    WILDCARD_PATTERN = re.compile(r"^\*\..+")
    CIDR_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")

    def __init__(self) -> None:
        self.parsed_assets: list[Asset] = []
        self.parse_errors: list[str] = []

    def parse_text_file(self, filepath: str) -> list[Asset]:
        """
        Parse scope from a plain text file.

        Expected format (one per line):
            *.example.com
            api.example.com
            192.168.1.0/24

        Lines starting with # or // are treated as comments.
        Lines starting with - or [OUT] are treated as out-of-scope.

        Args:
            filepath: Path to text file

        Returns:
            List of parsed Asset objects
        """
        assets: list[Asset] = []
        path = Path(filepath)

        if not path.exists():
            self.parse_errors.append(f"File not found: {filepath}")
            return assets

        with open(filepath) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue

                status = AssetStatus.IN_SCOPE
                notes = ""

                # Detect out-of-scope markers
                if line.startswith(("-", "!", "[OUT]", "[OOS]")):
                    status = AssetStatus.OUT_OF_SCOPE
                    line = line.lstrip("-! ").replace("[OUT]", "").replace("[OOS]", "").strip()
                    notes = "Out of scope"

                # Detect conditional markers
                if line.startswith("[COND]"):
                    status = AssetStatus.CONDITIONAL
                    line = line.replace("[COND]", "").strip()
                    notes = "Conditional scope"

                asset_type = self._detect_asset_type(line)
                if asset_type:
                    assets.append(Asset(
                        value=line,
                        asset_type=asset_type,
                        status=status,
                        notes=notes,
                        added_date=datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                    ))
                else:
                    self.parse_errors.append(f"Line {line_num}: Could not parse '{line}'")

        self.parsed_assets.extend(assets)
        return assets

    def parse_hackerone_scope(self, data: dict[str, Any]) -> list[Asset]:
        """
        Parse scope from HackerOne program API response.

        Args:
            data: HackerOne API response dictionary

        Returns:
            List of parsed Asset objects
        """
        assets = []
        program = data.get("attributes", {}).get("name", "unknown")

        for scope in data.get("relationships", {}).get("structured_scopes", {}).get("data", []):
            attrs = scope.get("attributes", {})
            asset_type = self._detect_asset_type(attrs.get("asset_identifier", ""))
            status = (
                AssetStatus.IN_SCOPE if attrs.get("eligible_for_submission")
                else AssetStatus.OUT_OF_SCOPE
            )
            assets.append(Asset(
                value=attrs.get("asset_identifier", ""),
                asset_type=asset_type or AssetType.DOMAIN,
                status=status,
                program=program,
                platform="hackerone",
                notes=attrs.get("instruction", ""),
                added_date=datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            ))

        self.parsed_assets.extend(assets)
        return assets

    def parse_bugcrowd_scope(self, data: dict[str, Any]) -> list[Asset]:
        """
        Parse scope from Bugcrowd program API response.

        Args:
            data: Bugcrowd API response dictionary

        Returns:
            List of parsed Asset objects
        """
        assets = []
        program = data.get("name", "unknown")

        for target in data.get("targets", {}).get("in_scope", []):
            asset_type = self._detect_asset_type(target.get("name", ""))
            assets.append(Asset(
                value=target.get("name", ""),
                asset_type=asset_type or AssetType.DOMAIN,
                status=AssetStatus.IN_SCOPE,
                program=program,
                platform="bugcrowd",
                notes=target.get("category", ""),
                added_date=datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            ))

        for target in data.get("targets", {}).get("out_of_scope", []):
            asset_type = self._detect_asset_type(target.get("name", ""))
            assets.append(Asset(
                value=target.get("name", ""),
                asset_type=asset_type or AssetType.DOMAIN,
                status=AssetStatus.OUT_OF_SCOPE,
                program=program,
                platform="bugcrowd",
                notes=f"Out of scope: {target.get('category', '')}",
                added_date=datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            ))

        self.parsed_assets.extend(assets)
        return assets

    def parse_json_file(self, filepath: str) -> list[Asset]:
        """
        Parse scope from a JSON file.

        Expected format:
        {
            "program": "example",
            "platform": "hackerone",
            "in_scope": ["*.example.com", "api.example.com"],
            "out_of_scope": ["admin.example.com"],
            "notes": "Optional notes"
        }

        Args:
            filepath: Path to JSON file

        Returns:
            List of parsed Asset objects
        """
        assets: list[Asset] = []
        path = Path(filepath)

        if not path.exists():
            self.parse_errors.append(f"File not found: {filepath}")
            return assets

        with open(filepath) as f:
            data = json.load(f)

        program = data.get("program", "unknown")
        platform = data.get("platform", "unknown")

        for item in data.get("in_scope", []):
            asset_type = self._detect_asset_type(item)
            assets.append(Asset(
                value=item,
                asset_type=asset_type or AssetType.DOMAIN,
                status=AssetStatus.IN_SCOPE,
                program=program,
                platform=platform,
                added_date=datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            ))

        for item in data.get("out_of_scope", []):
            asset_type = self._detect_asset_type(item)
            assets.append(Asset(
                value=item,
                asset_type=asset_type or AssetType.DOMAIN,
                status=AssetStatus.OUT_OF_SCOPE,
                program=program,
                platform=platform,
                added_date=datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            ))

        self.parsed_assets.extend(assets)
        return assets

    def _detect_asset_type(self, value: str) -> AssetType | None:
        """Detect the type of an asset from its value."""
        value = value.strip()

        if not value:
            return None

        if self.CIDR_PATTERN.match(value) or self.IP_RANGE_PATTERN.match(value):
            return AssetType.IP_RANGE
        if self.IP_PATTERN.match(value):
            return AssetType.IP_RANGE
        if self.WILDCARD_PATTERN.match(value):
            return AssetType.WILDCARD
        if "android" in value.lower() or "ios" in value.lower():
            return AssetType.MOBILE_APP
        if "/api" in value.lower() or value.startswith("api."):
            return AssetType.API
        if value.endswith(".apk") or value.endswith(".ipa"):
            return AssetType.MOBILE_APP

        return AssetType.DOMAIN


class ScopeManager:
    """
    Manages bug bounty scope across multiple programs and platforms.

    Tracks in-scope/out-of-scope assets, matches CVEs to scope,
    and monitors scope changes.

    Example:
        manager = ScopeManager()
        manager.add_program("hackerone", "acme", ["*.acme.com"], ["internal.acme.com"])
        matches = manager.match_cves_to_scope(cve_list)
        print(f"Found {len(matches)} CVEs affecting in-scope assets")
    """

    def __init__(self) -> None:
        self.assets: list[Asset] = []
        self.programs: dict[str, dict[str, Any]] = {}  # program_name -> program info
        self.scope_history: list[dict[str, Any]] = []  # Track scope changes
        self.parser = ScopeParser()

    def add_program(
        self,
        platform: str,
        program_name: str,
        in_scope: list[str],
        out_of_scope: list[str] | None = None,
        notes: str = "",
    ) -> None:
        """
        Add a bug bounty program with scope.

        Args:
            platform: Platform name (hackerone, bugcrowd, intigriti)
            program_name: Program identifier
            in_scope: List of in-scope asset strings
            out_of_scope: List of out-of-scope asset strings
            notes: Additional notes about the program
        """
        self.programs[program_name] = {
            "platform": platform,
            "added": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "notes": notes,
            "in_scope_count": len(in_scope),
            "out_of_scope_count": len(out_of_scope or []),
        }

        for item in in_scope:
            asset_type = self.parser._detect_asset_type(item)
            self.assets.append(Asset(
                value=item,
                asset_type=asset_type or AssetType.DOMAIN,
                status=AssetStatus.IN_SCOPE,
                program=program_name,
                platform=platform,
                added_date=datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            ))

        for item in (out_of_scope or []):
            asset_type = self.parser._detect_asset_type(item)
            self.assets.append(Asset(
                value=item,
                asset_type=asset_type or AssetType.DOMAIN,
                status=AssetStatus.OUT_OF_SCOPE,
                program=program_name,
                platform=platform,
                notes="Explicitly out of scope",
                added_date=datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            ))

    def load_scope_file(self, filepath: str, program_name: str = "", platform: str = "") -> list[Asset]:
        """
        Load scope from a file (auto-detects format).

        Args:
            filepath: Path to scope file
            program_name: Program name to associate
            platform: Platform name

        Returns:
            List of loaded assets
        """
        path = Path(filepath)
        suffix = path.suffix.lower()

        if suffix == ".json":
            assets = self.parser.parse_json_file(filepath)
        else:
            assets = self.parser.parse_text_file(filepath)

        # Update program info if provided
        if program_name:
            for asset in assets:
                if not asset.program:
                    asset.program = program_name
                if not asset.platform:
                    asset.platform = platform

            if program_name not in self.programs:
                self.programs[program_name] = {
                    "platform": platform,
                    "added": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                }

        self.assets.extend(assets)
        return assets

    def is_in_scope(self, target: str) -> tuple[bool, Asset | None]:
        """
        Check if a target is in scope.

        Args:
            target: Domain, IP, or URL to check

        Returns:
            Tuple of (is_in_scope, matching_asset_or_none)
        """
        # Extract domain from URL if needed
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            target = parsed.hostname or target

        # Check out-of-scope first (explicit exclusions take priority)
        for asset in self.assets:
            if asset.status == AssetStatus.OUT_OF_SCOPE and asset.matches_domain(target):
                return False, asset

        # Check in-scope
        for asset in self.assets:
            if asset.status == AssetStatus.IN_SCOPE and asset.matches_domain(target):
                return True, asset

        return False, None

    def get_in_scope(self, program: str | None = None) -> list[Asset]:
        """Get all in-scope assets, optionally filtered by program."""
        assets = [a for a in self.assets if a.status == AssetStatus.IN_SCOPE]
        if program:
            assets = [a for a in assets if a.program == program]
        return assets

    def get_out_of_scope(self, program: str | None = None) -> list[Asset]:
        """Get all out-of-scope assets."""
        assets = [a for a in self.assets if a.status == AssetStatus.OUT_OF_SCOPE]
        if program:
            assets = [a for a in assets if a.program == program]
        return assets

    def get_wildcards(self) -> list[Asset]:
        """Get all wildcard assets."""
        return [a for a in self.assets if a.asset_type == AssetType.WILDCARD]

    def match_cves_to_scope(
        self,
        cves: list[dict[str, Any]],
        match_field: str = "product",
    ) -> list[dict[str, Any]]:
        """
        Match CVEs to in-scope assets based on affected products.

        Args:
            cves: List of CVE dictionaries
            match_field: Field in CVE dict to match against asset tech_stack

        Returns:
            List of CVEs that affect in-scope technology
        """
        # Build set of technologies from scope
        scope_tech = set()
        for asset in self.assets:
            if asset.status == AssetStatus.IN_SCOPE:
                scope_tech.update(asset.tech_stack)
                # Also add domain-derived tech hints
                domain = asset.value.lstrip("*.")
                scope_tech.add(domain.split(".")[0])  # e.g., "api" from "api.example.com"

        matches = []
        for cve in cves:
            product = _get_value(cve, match_field, "")
            if not product:
                continue

            product_lower = product.lower()
            # Handle both dicts and Pydantic models
            cve_copy = cve.model_dump(mode="json") if hasattr(cve, "model_dump") else dict(cve)
            cve_copy["in_scope"] = False
            cve_copy["matched_assets"] = []

            # Direct product match against tech stack
            for tech in scope_tech:
                if tech.lower() in product_lower or product_lower in tech.lower():
                    cve_copy["in_scope"] = True
                    break

            # Check if any asset domain matches affected host
            affected_hosts = _get_value(cve, "affected_hosts", [])
            for host in affected_hosts:
                in_scope, matched_asset = self.is_in_scope(host)
                if in_scope:
                    cve_copy["in_scope"] = True
                    if matched_asset:
                        cve_copy["matched_assets"].append(matched_asset.value)

            if cve_copy["in_scope"]:
                matches.append(cve_copy)

        return matches

    def add_tech_stack(self, asset_value: str, technologies: list[str]) -> None:
        """
        Add technology stack information to an asset.

        Args:
            asset_value: Asset identifier to update
            technologies: List of technology names (e.g., ['Apache', 'PHP', 'MySQL'])
        """
        for asset in self.assets:
            if asset.value == asset_value or asset.matches_domain(asset_value):
                asset.tech_stack.extend(technologies)
                # Case-insensitive deduplication: keep first-seen casing
                seen = set()
                deduped = []
                for t in asset.tech_stack:
                    t_lower = t.lower()
                    if t_lower not in seen:
                        seen.add(t_lower)
                        deduped.append(t)
                asset.tech_stack = deduped

    def detect_scope_changes(
        self,
        previous_scope: list[Asset],
        current_scope: list[Asset],
    ) -> dict[str, Any]:
        """
        Detect changes between two scope snapshots.

        Args:
            previous_scope: Previous scope asset list
            current_scope: Current scope asset list

        Returns:
            Dictionary with added, removed, and changed assets
        """
        prev_values = {a.value: a for a in previous_scope}
        curr_values = {a.value: a for a in current_scope}

        added = [curr_values[v].to_dict() for v in curr_values if v not in prev_values]
        removed = [prev_values[v].to_dict() for v in prev_values if v not in curr_values]

        # Status changes
        changed = []
        for value in curr_values:
            if value in prev_values and curr_values[value].status != prev_values[value].status:
                changed.append({
                    "asset": value,
                    "old_status": prev_values[value].status.value,
                    "new_status": curr_values[value].status.value,
                })

        change_record = {
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "added": added,
            "removed": removed,
            "changed": changed,
            "summary": {
                "total_added": len(added),
                "total_removed": len(removed),
                "total_changed": len(changed),
            },
        }

        self.scope_history.append(change_record)
        return change_record

    def export_scope(self, filepath: str) -> None:
        """Export current scope to JSON file."""
        data = {
            "exported_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "programs": self.programs,
            "assets": [a.to_dict() for a in self.assets],
            "history": self.scope_history,
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def import_scope(self, filepath: str) -> None:
        """Import scope from JSON file."""
        with open(filepath) as f:
            data = json.load(f)

        self.programs = data.get("programs", {})
        self.assets = [Asset.from_dict(a) for a in data.get("assets", [])]
        self.scope_history = data.get("history", [])

    def get_scope_summary(self) -> dict[str, Any]:
        """Get summary statistics of current scope."""
        in_scope = len([a for a in self.assets if a.status == AssetStatus.IN_SCOPE])
        out_of_scope = len([a for a in self.assets if a.status == AssetStatus.OUT_OF_SCOPE])
        wildcards = len([a for a in self.assets if a.asset_type == AssetType.WILDCARD])
        programs = len(self.programs)

        return {
            "total_assets": len(self.assets),
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "wildcards": wildcards,
            "programs": programs,
            "program_names": list(self.programs.keys()),
            "assets_with_cve_matches": len([
                a for a in self.assets if a.cve_matches
            ]),
        }

    def generate_nuclei_scope_file(self, filepath: str) -> None:
        """
        Generate a scope file for Nuclei scanner.

        Creates a list of domains for Nuclei -scan-domain flag.

        Args:
            filepath: Output file path
        """
        domains = []
        for asset in self.assets:
            if asset.status == AssetStatus.IN_SCOPE and asset.asset_type in (
                AssetType.WILDCARD,
                AssetType.DOMAIN,
            ):
                domains.append(asset.value)

        with open(filepath, "w") as f:
            f.write("\n".join(sorted(set(domains))))

    def generate_nmap_targets_file(self, filepath: str) -> None:
        """
        Generate a targets file for Nmap scanning.

        Args:
            filepath: Output file path
        """
        targets = []
        for asset in self.assets:
            if asset.status == AssetStatus.IN_SCOPE and asset.asset_type in (
                AssetType.IP_RANGE,
                AssetType.DOMAIN,
            ):
                targets.append(asset.value)

        with open(filepath, "w") as f:
            f.write("\n".join(sorted(set(targets))))
