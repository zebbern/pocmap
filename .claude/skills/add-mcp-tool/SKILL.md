---
name: add-mcp-tool
description: >
  Add a new MCP tool to the pocmap server the house way. Use when asked to
  "add an MCP tool", "expose <X> as a tool", "wire a service method into the MCP
  server", or when extending mcp_server.py. Encodes the 4-surface change (adapter
  method + normalizer, @mcp.tool wrapper, mcp_config.json, agent docs) so the
  19-tool surface stays consistent and doesn't drift.
---

# Add an MCP tool to pocmap

Adding one tool touches **four places in lockstep**. Miss one and you get drift
(the exact problem the `agent-docs-consistency` reviewer exists to catch). The
MCP server implementation is `src/pocmap/mcp_server.py` (console script `pocmap-mcp`).
Repo-root `mcp_server.py` is only a launcher shim.

Work through this checklist in order.

## 1. Service method (the real work) — `src/pocmap/services/`
The tool should be a thin wrapper over a **synchronous** service method that
returns Pydantic models. If the capability doesn't exist yet, add the method to
the right service (or a new client under `src/pocmap/clients/` that uses
`HTTPClient` so it inherits the SSRF guard). Do not put business logic in
`pocmap.mcp_server`.

## 2. `ServiceAdapter` method + normalizer — in `src/pocmap/mcp_server.py`
`ServiceAdapter` converts service models → plain dicts for JSON tool responses.
Follow the existing shape:

```python
# inside class ServiceAdapter:
def my_thing(self, cve_id: str, limit: int = 10) -> list[dict[str, Any]]:
    """One-line description. Returns normalized dicts."""
    try:
        items = self._exploit.find_something(cve_id, limit=limit)
        return [self._normalize_exploit(i) for i in items[:limit]]
    except Exception as e:
        logger.warning(f"my_thing failed for {cve_id}: {e}")
        return []
```

Reuse an existing `_normalize_*` static method (`_normalize_cve_info`,
`_normalize_exploit`, `_normalize_bb_report`, `_normalize_lab`, `_normalize_cpe`,
`_normalize_recent_result`, `_normalize_discovery_result`). Add a new one only if
the return type is genuinely new; use `ServiceAdapter._enum_val(...)` for enums.

## 3. `@mcp.tool` wrapper — in `src/pocmap/mcp_server.py`
Register the tool. Match the house conventions exactly:

```python
@mcp.tool(
    name="my_thing",
    description=(
        "One or two sentences on WHAT it returns and WHEN to use it. "
        "State the CVE-YYYY-NNNN+ format requirement if it takes a cve_id. "
        "Name the data sources."
    ),
)
def my_thing(cve_id: str, limit: int = 10) -> str:
    """Docstring: Args + the exact JSON keys returned."""
    try:
        data = _svc.my_thing(cve_id, limit)
        # If the adapter can return an {"error": ...} envelope, map it:
        if isinstance(data, dict) and "error" in data:
            return json.dumps({
                "error": data["error"],
                "category": "not_found" if "not found" in str(data["error"]).lower() else "unknown",
                "cve_id": cve_id.upper().strip(),
            })
        return json.dumps(data, indent=2, default=str)
    except Exception as e:
        logger.error(f"my_thing error: {e}")
        return _format_error_json(e, f"my_thing({cve_id})")
```

Non-negotiable conventions (verified across the existing 19 tools):
- The function **returns a JSON `str`**, never a dict/object.
- Normalize inputs: `cve_id.upper().strip()`.
- Serialize with `json.dumps(..., default=str)` (handles enums/dates/Paths).
- Wrap the body in `try/except` and return `_format_error_json(e, "<context>")`.
- Keep the `description=` rich — it is the model's only signal for tool routing.

## 4. Keep the docs in sync (or you create drift)
Update **all** of these so the tool count and contract stay truthful:
- `mcp_config.json` (repo root) — add the tool to the catalog.
- `AGENTS.md` (repo root) — add it to the tool tables.
- `.claude/skills/pocmap-agent/references/mcp_tools.md` — add a full entry and a
  row in the Quick Lookup Table; bump the "19 tools" counts (here and in
  `SKILL.md`) if the total changed.

## 5. Verify
- `ruff check src/pocmap/mcp_server.py` (the PostToolUse hook also runs this on edit).
- Smoke-test the server imports and lists the tool:
  `python -c "import pocmap.mcp_server as m; print([t for t in dir(m) if not t.startswith('_')][:5])"`
  or start it: `pocmap-mcp` / `python -m pocmap.mcp_server` (STDIO) and call the tool from a client.
- Run the `agent-docs-consistency` subagent to confirm no drift was introduced.
