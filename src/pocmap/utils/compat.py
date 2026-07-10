"""Compatibility helpers for working with both dicts and Pydantic models.

These utilities provide a unified interface for accessing data from
dictionaries and Pydantic model instances, eliminating repetitive
isinstance checks throughout the codebase.

Example::

    from pocmap.utils.compat import get_value, to_dict

    # Works with both dicts and Pydantic models
    val = get_value(cve_data, "id", "")
    d = to_dict(cve_model)
"""

from __future__ import annotations

from typing import Any


def get_value(obj: Any, key: str, default: Any = None) -> Any:
    """Get a value from a dict or an object with attributes.

    Provides uniform access regardless of whether *obj* is a plain
    ``dict`` or a Pydantic ``BaseModel`` (or any other object).

    Args:
        obj: The object to read from.
        key: Attribute / dict key to look up.
        default: Value to return if the key/attribute is missing
                 or if *obj* is ``None``.

    Returns:
        The looked-up value, or *default*.

    Example::

        get_value({"id": "CVE-2021-44228"}, "id")          # -> "CVE-2021-44228"
        get_value(cve_info_model, "id")                     # -> "CVE-2021-44228"
        get_value(None, "id", "")                           # -> ""
    """
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def to_dict(obj: Any) -> dict[str, Any]:
    """Convert a Pydantic model to a dict, or pass through dicts.

    Args:
        obj: A Pydantic model instance, a dict, or ``None``.

    Returns:
        A plain dictionary. Returns an empty dict if *obj* is ``None``.

    Example::

        to_dict(cve_info_model)   # -> {"id": "CVE-2021-44228", ...}
        to_dict({"id": "CVE-..."}) # -> {"id": "CVE-..."}  (pass-through)
        to_dict(None)              # -> {}
    """
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        dumped: dict[str, Any] = obj.model_dump(mode="json")
        return dumped
    if hasattr(obj, "dict"):
        legacy: dict[str, Any] = obj.dict()
        return legacy
    return dict(obj)
