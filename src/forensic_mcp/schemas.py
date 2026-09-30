"""JSON Schema validators for the output contract (ET-03) and audit events (ET-04).

The schemas live in docs/ (single source of truth, reviewed in L2).
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

DOCS = Path(__file__).resolve().parents[2] / "docs"


@lru_cache(maxsize=None)
def _load(name: str) -> dict[str, Any]:
    return json.loads((DOCS / name).read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def output_validator() -> Draft202012Validator:
    """Validator of docs/output_schema.json."""
    return Draft202012Validator(_load("output_schema.json"))


@lru_cache(maxsize=None)
def event_validator() -> Draft202012Validator:
    """Validator of #/$defs/event in docs/audit_schema.json (the decoded `body` of a line)."""
    schema = _load("audit_schema.json")
    return Draft202012Validator({"$defs": schema["$defs"], **schema["$defs"]["event"]})


@lru_cache(maxsize=None)
def line_validator() -> Draft202012Validator:
    """Validator of one audit.jsonl line (envelope)."""
    return Draft202012Validator(_load("audit_schema.json"))


def errors(validator: Draft202012Validator, instance: Any) -> list[str]:
    """Readable validation errors (empty list when valid)."""
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
            for e in validator.iter_errors(instance)]


def validate_output(payload: dict[str, Any]) -> None:
    """Raise ValueError if a tool response breaks the output contract."""
    errs = errors(output_validator(), payload)
    if errs:
        raise ValueError("output contract violated: " + "; ".join(errs[:5]))
