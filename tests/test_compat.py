"""Offline native tests for the dict/model compatibility helpers.

Regression guards for ``pocmap.utils.compat.get_value`` and ``to_dict``,
covering every branch (None, dict pass-through, pydantic ``model_dump``,
legacy ``.dict()``, and the final ``dict(obj)`` fallback).
"""

from __future__ import annotations

from typing import Any

from pocmap.models import CVEInfo, CVSSScore
from pocmap.utils.compat import get_value, to_dict

# ---------------------------------------------------------------------------
# get_value
# ---------------------------------------------------------------------------

def test_get_value_none_returns_default() -> None:
    assert get_value(None, "id", "") == ""
    assert get_value(None, "id") is None


def test_get_value_dict_lookup() -> None:
    assert get_value({"id": "X"}, "id") == "X"
    assert get_value({"id": "X"}, "missing", "fallback") == "fallback"


def test_get_value_object_getattr() -> None:
    model = CVEInfo(id="CVE-2021-44228")
    assert get_value(model, "id") == "CVE-2021-44228"
    assert get_value(model, "does_not_exist", "d") == "d"


# ---------------------------------------------------------------------------
# to_dict
# ---------------------------------------------------------------------------

def test_to_dict_none_returns_empty_dict() -> None:
    assert to_dict(None) == {}


def test_to_dict_dict_pass_through_identity() -> None:
    d = {"a": 1}
    assert to_dict(d) is d


def test_to_dict_pydantic_model_uses_model_dump() -> None:
    result = to_dict(CVSSScore())
    assert isinstance(result, dict)
    # model_dump(mode="json") serializes the enum to its string value.
    assert result["severity"] == "UNKNOWN"


def test_to_dict_legacy_dict_method_branch() -> None:
    class LegacyModel:
        def dict(self) -> dict[str, Any]:
            return {"legacy": True}

    assert to_dict(LegacyModel()) == {"legacy": True}


def test_to_dict_final_dict_fallback() -> None:
    assert to_dict([("a", 1)]) == {"a": 1}
