"""Tool registration helper and identifier validation."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar, cast

from mcp.types import ToolAnnotations

from pocmap.mcp.errors import _format_error_json
from pocmap.mcp.server import mcp
from pocmap.utils.http import ValidationError
from pocmap.utils.validators import validate_cve_id as _validate_cve_id

# Behavioural hints hosts use to decide what needs confirmation. Without them a
# host must assume the worst of every tool, so 21 read-only lookups look as
# risky as the one that writes to disk.
_READ_ONLY = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True
)
# Same, but served from data shipped inside the package — no network at all.
_LOCAL_ONLY = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
# verify_github_pocs downloads third-party exploit source and extracts it under
# POCMAP_POC_SOURCE_DIR. Not destructive (it only writes into its own cache),
# but genuinely not read-only, and a host should be able to tell.
_WRITES_TO_DISK = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True
)


# Preserves each tool function's own signature through the decorator; without
# it mypy sees an untyped decorator and erases all 22 tools to ``Any``.
_ToolFn = TypeVar("_ToolFn", bound=Callable[..., Any])


def _validate_tool_input(bound: dict[str, Any], tool_name: str) -> dict[str, Any] | None:
    """Return an ``invalid_input`` envelope if an identifier argument is malformed.

    Without this, a typo was reported as a *finding*: ``check_kev_status`` on
    "CVE202144228" returned ``kev_status: false`` — which an agent reads as "not
    actively exploited" — and ``cve_to_cpe`` / ``cpe_to_cve`` returned
    ``total_count: 0``, indistinguishable from a genuine empty result. Only
    3 of the 13 CVE-taking tools validated their input.

    Applied in the shared decorator rather than per tool, so a tool added later
    inherits it instead of re-introducing the gap.
    """
    raw_cve = bound.get("cve_id")
    if isinstance(raw_cve, str):
        try:
            _validate_cve_id(raw_cve)
        except ValueError as exc:
            return _format_error_json(
                ValidationError(f"{exc} Expected format: CVE-YYYY-NNNN."),
                f"{tool_name}({raw_cve!r})",
            )

    raw_cpe = bound.get("cpe")
    if isinstance(raw_cpe, str):
        text = raw_cpe.strip()
        # A CPE 2.3 URI is `cpe:2.3:<part>:<vendor>:<product>:...`; the 2.2 form
        # is `cpe:/<part>:...`. Anything else cannot address a product.
        if not (text.startswith("cpe:2.3:") or text.startswith("cpe:/")):
            return _format_error_json(
                ValidationError(
                    f"Invalid CPE format: {raw_cpe!r}. "
                    "Expected a CPE 2.3 URI, e.g. 'cpe:2.3:a:apache:log4j:2.0'."
                ),
                f"{tool_name}({raw_cpe!r})",
            )
    return None


def _tool(
    *, name: str, description: str, annotations: ToolAnnotations = _READ_ONLY
) -> Callable[[_ToolFn], _ToolFn]:
    """Register a tool with pocmap's house defaults.

    Structured output is left on. Every tool returns ``dict[str, Any]``, so the
    SDK emits the object itself as ``structuredContent`` under an
    ``{"type": "object"}`` schema. Tools previously returned a JSON *string*,
    which made the SDK derive ``{"result": {"type": "string"}}`` and wrap the
    payload as ``structuredContent: {"result": "<json string>"}`` — encoded
    twice, behind a schema describing none of it.

    The schema is deliberately permissive rather than per-tool. A tool returns
    either its success shape *or* an error envelope, and pydantic materializes
    declared fields with defaults — so a per-tool model would stamp
    ``total_count: 0`` onto a throttled lookup, turning "could not answer" into
    "no results". :mod:`pocmap.models` exports 13 JSON Schemas describing the
    nested payloads for callers who want them, and the pocmap-agent skill
    (``mcp_tools.md``) documents each tool's keys; neither costs the error
    envelope its honesty.
    """
    register: Callable[[_ToolFn], _ToolFn] = mcp.tool(
        name=name, description=description, annotations=annotations
    )

    def decorate(fn: _ToolFn) -> _ToolFn:
        signature = inspect.signature(fn)
        if not ({"cve_id", "cpe"} & set(signature.parameters)):
            return register(fn)

        @functools.wraps(fn)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            error = _validate_tool_input(dict(bound.arguments), name)
            return error if error is not None else fn(*args, **kwargs)

        return register(cast("_ToolFn", guarded))

    return decorate
