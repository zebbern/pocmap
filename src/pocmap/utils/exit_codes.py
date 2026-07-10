"""Stable, named process exit codes for the PocMap CLI.

Having a documented, machine-readable exit-code scheme lets scripts and CI
pipelines react to *why* a command stopped rather than only *whether* it
succeeded. The scheme is intentionally small and additive:

======  ==========================  ============================================
Code    Name                        Meaning
======  ==========================  ============================================
``0``   :attr:`ExitCode.OK`         Success. The command ran and produced output.
``1``   :attr:`ExitCode.ERROR`      Generic/unclassified error. This is the
                                    historical ``typer.Exit(1)`` value, kept so
                                    every pre-existing error site still means
                                    "something went wrong" without needing to be
                                    reclassified in one sweep.
``2``   :attr:`ExitCode.NO_RESULTS` The command ran successfully but found
                                    nothing (empty result set). Distinct from a
                                    hard failure so callers can tell "looked,
                                    found zero" from "could not look".
``3``   :attr:`ExitCode.NOT_FOUND`  The requested resource does not exist
                                    upstream (e.g. no such CVE record).
``4``   :attr:`ExitCode.INVALID_INPUT`  Caller-supplied input was malformed
                                    (e.g. a bad CVE ID or unsafe path).
``5``   :attr:`ExitCode.UPSTREAM_ERROR`  A dependency/upstream data source
                                    failed (network error, rate limit, 5xx).
======  ==========================  ============================================

The values are stable public contract: never renumber an existing code. New
conditions get new numbers appended.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["ExitCode"]


class ExitCode(IntEnum):
    """Named process exit codes returned by PocMap CLI commands.

    Being an :class:`~enum.IntEnum`, each member *is* an ``int`` and can be
    handed straight to :class:`typer.Exit` (e.g. ``raise typer.Exit(ExitCode.
    INVALID_INPUT)``) or compared against ``result.exit_code`` in tests.
    """

    OK = 0
    """Success: the command completed and produced its intended output."""

    ERROR = 1
    """Generic, unclassified error (the historical ``typer.Exit(1)`` value)."""

    NO_RESULTS = 2
    """The command ran fine but the result set was empty."""

    NOT_FOUND = 3
    """The requested resource does not exist upstream (e.g. unknown CVE)."""

    INVALID_INPUT = 4
    """Caller-supplied input was malformed (bad CVE ID, unsafe path, ...)."""

    UPSTREAM_ERROR = 5
    """An upstream data source failed (network error, rate limit, 5xx)."""
