"""Pure output renderers: view model -> string.

Each renderer is a side-effect-free function that maps a plain view model (a
list of dicts, or CVE dicts for SARIF) to a formatted string. They perform no
I/O and no network access, so the CLI wiring layer (a later roadmap item) owns
argument parsing, file writing and stdout — these functions only produce text.

* :func:`render_csv` — CSV with a stable union header (stdlib ``csv``).
* :func:`render_markdown` — GitHub-flavored Markdown table.
* :func:`render_sarif` — SARIF 2.1.0 log for CI code-scanning pipelines.
"""

from __future__ import annotations

from pocmap.utils.renderers.csv_renderer import render_csv
from pocmap.utils.renderers.markdown_renderer import render_markdown
from pocmap.utils.renderers.sarif_renderer import render_sarif

__all__ = ["render_csv", "render_markdown", "render_sarif"]
