"""JSON Schema loading + validation against the canonical shared contract.

Schemas live in shared/schema/ (read-only in Docker). We validate inbound messages
here so a malformed message becomes a clean 400 + stable code, never a crash
(plan §7.4 anti-fragile transport).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Tuple

from jsonschema import Draft202012Validator

from .config import shared_dir
from .errors import SCHEMA_INVALID, GuardianError

_CACHE: dict = {}

# The schemas this layer owns/consumes (validated in tests, plan §12).
SCHEMA_NAMES = ["reading", "passport", "action", "witness", "describe"]


def schema_dir() -> Path:
    return shared_dir() / "schema"


def load_schema(name: str) -> dict:
    if name in _CACHE:
        return _CACHE[name]
    path = schema_dir() / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing JSON schema: {path}")
    with path.open("r", encoding="utf-8") as fh:
        schema = json.load(fh)
    Draft202012Validator.check_schema(schema)
    _CACHE[name] = schema
    return schema


def validate(instance: Any, name: str) -> Tuple[bool, List[Any]]:
    validator = Draft202012Validator(load_schema(name))
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    return (len(errors) == 0), errors


def validate_or_raise(instance: Any, name: str) -> None:
    ok, errors = validate(instance, name)
    if not ok:
        first = errors[0]
        loc = "/".join(str(p) for p in first.absolute_path) or "<root>"
        raise GuardianError(
            SCHEMA_INVALID,
            f"{name} failed schema validation at '{loc}': {first.message}",
            http_status=400,
            details={"schema": name, "location": loc, "error": first.message},
        )
