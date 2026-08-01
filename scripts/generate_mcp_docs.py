#!/usr/bin/env python3
"""Generate MkDocs MCP reference pages from the live server + pydantic models.

Run from the repo root (requires the ``[server]`` extra)::

    python scripts/generate_mcp_docs.py

``mkdocs build --strict`` expects the generated files under ``docs/reference/``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import anyio

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "reference"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def write_tools_page(tools: list[object]) -> None:
    lines = [
        "# MCP tools",
        "",
        "Auto-generated from the registered PocMap MCP server "
        "(`python scripts/generate_mcp_docs.py`). "
        "Canonical agent guide with return-shape notes: "
        "`.claude/skills/pocmap-agent/references/mcp_tools.md`.",
        "",
        f"**{len(tools)} tools** registered.",
        "",
        "| Tool | Description |",
        "|------|-------------|",
    ]
    for tool in sorted(tools, key=lambda t: t.name):  # type: ignore[attr-defined]
        desc = (tool.description or "").split(". ")[0].strip()  # type: ignore[attr-defined]
        if desc and not desc.endswith("."):
            desc += "."
        lines.append(f"| `{tool.name}` | {_md_escape(desc)} |")  # type: ignore[attr-defined]

    lines.extend(["", "## Tool details", ""])
    for tool in sorted(tools, key=lambda t: t.name):  # type: ignore[attr-defined]
        data = tool.model_dump(mode="json")  # type: ignore[attr-defined]
        lines.append(f"### `{data['name']}`")
        lines.append("")
        lines.append(data.get("description") or "_No description._")
        lines.append("")
        schema = data.get("input_schema") or {}
        lines.append("**Input schema**")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(schema, indent=2))
        lines.append("```")
        lines.append("")
        ann = data.get("annotations") or {}
        if ann:
            bits = ", ".join(f"`{k}={v}`" for k, v in ann.items() if v is not None)
            if bits:
                lines.append(f"**Annotations:** {bits}")
                lines.append("")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "mcp-tools.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_schemas_page() -> None:
    from pocmap.models import (
        BugBountyReport,
        CPEInfo,
        CVEInfo,
        Exploit,
        LabEnvironment,
        PackageVulnerability,
        ReportEntry,
    )

    models = [
        CVEInfo,
        Exploit,
        LabEnvironment,
        BugBountyReport,
        CPEInfo,
        ReportEntry,
        PackageVulnerability,
    ]
    lines = [
        "# Data model schemas",
        "",
        "JSON Schema (Pydantic serialization mode) for the main PocMap models. "
        "Regenerate with `python scripts/generate_mcp_docs.py`, or write all "
        "schemas to disk via `pocmap schemas --output ./schemas`.",
        "",
        "MCP tools return plain objects under an open `{\"type\": \"object\"}` "
        "output schema so error envelopes are never stamped with success defaults.",
        "",
    ]
    for model in models:
        schema = model.model_json_schema(mode="serialization")
        lines.append(f"## `{model.__name__}`")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(schema, indent=2))
        lines.append("```")
        lines.append("")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "schemas.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    try:
        from pocmap.mcp_server import mcp
    except ImportError as exc:
        print(
            "Install the server extra first: pip install -e '.[server,docs,dev]'",
            file=sys.stderr,
        )
        print(exc, file=sys.stderr)
        return 1

    tools = anyio.run(mcp.list_tools)
    write_tools_page(list(tools))
    write_schemas_page()
    print(f"Wrote {OUT / 'mcp-tools.md'} and {OUT / 'schemas.md'} ({len(tools)} tools)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
