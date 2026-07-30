"""Native offline regression tests for the Jinja2 template sandbox.

``src/pocmap/bugbounty/templates.py`` uses a :class:`SandboxedEnvironment` to
render bug-bounty report templates — a documented security invariant (SSTI
prevention) with no native guard until now. A silent swap to a plain
``jinja2.Environment`` would still pass CI, so these tests assert the sandbox is
in place and that its dunder-attribute blocking actually fires.

``jinja2`` is a hard dependency, so this is fully offline.
"""

from __future__ import annotations

import jinja2.exceptions
import pytest
from jinja2.sandbox import SandboxedEnvironment

from pocmap.bugbounty.templates import jinja_env


def test_jinja_env_is_sandboxed() -> None:
    """The module-level environment must be a SandboxedEnvironment."""
    assert isinstance(jinja_env, SandboxedEnvironment)


@pytest.mark.parametrize(
    "payload",
    [
        "{{ ().__class__.__bases__ }}",
        '{{ "".__class__.__mro__ }}',
        "{{ self.__init__.__globals__ }}",
    ],
)
def test_dunder_escape_payloads_raise_security_error(payload: str) -> None:
    """Classic SSTI sandbox-escape payloads must raise SecurityError."""
    template = jinja_env.from_string(payload)
    with pytest.raises(jinja2.exceptions.SecurityError):
        template.render()


def test_html_autoescape_of_context_value() -> None:
    """A context value with HTML metacharacters is auto-escaped."""
    rendered = jinja_env.from_string("<b>{{ x }}</b>").render(
        x="<script>alert(1)</script>"
    )
    assert "&lt;script&gt;" in rendered
    assert "<script>" not in rendered
