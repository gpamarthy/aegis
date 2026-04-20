"""Payload loader for AEGIS YAML payload libraries.

Usage::

    from aegis.payloads import load_payloads

    jailbreaks = load_payloads("jailbreaks")
    injections = load_payloads("injections")
    extractions = load_payloads("extractions")
"""

import os
from pathlib import Path
from typing import Any

import yaml

_PAYLOAD_DIR = Path(__file__).resolve().parent

# Valid category names (map to YAML files in this directory)
CATEGORIES = ("jailbreaks", "injections", "extractions")


def _yaml_path(category: str) -> Path:
    """Return the resolved path to the YAML file for *category*."""
    path = _PAYLOAD_DIR / f"{category}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"Payload file not found: {path}. "
            f"Valid categories: {', '.join(CATEGORIES)}"
        )
    return path


def load_payloads(category: str) -> list[dict[str, Any]]:
    """Load and return all payloads from the YAML file matching *category*.

    Parameters
    ----------
    category:
        One of ``"jailbreaks"``, ``"injections"``, or ``"extractions"``.

    Returns
    -------
    list[dict]
        Each dict contains at minimum ``id``, ``name``, ``technique``,
        ``category``, ``payload``, ``markers``, and ``severity``.
    """
    path = _yaml_path(category)
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, list):
        raise ValueError(
            f"Expected a YAML list in {path}, got {type(data).__name__}"
        )
    return data


def load_payload_by_id(category: str, payload_id: str) -> dict[str, Any] | None:
    """Load a single payload by its ``id`` field.

    Returns ``None`` if the id is not found.
    """
    for entry in load_payloads(category):
        if entry.get("id") == payload_id:
            return entry
    return None


def list_payload_ids(category: str) -> list[str]:
    """Return a list of all payload ids in a category."""
    return [p["id"] for p in load_payloads(category) if "id" in p]


def list_categories() -> list[str]:
    """Return available payload categories based on YAML files on disk."""
    return [
        p.stem
        for p in sorted(_PAYLOAD_DIR.glob("*.yaml"))
        if p.stem != "__pycache__"
    ]
