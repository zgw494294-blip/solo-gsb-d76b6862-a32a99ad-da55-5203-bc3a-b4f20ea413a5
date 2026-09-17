"""Runtime configuration loaded from environment variables.

Nothing written to this file or any log is permitted to contain source
data or original values — see README "安全边界".
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _get(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


@dataclass(frozen=True)
class Settings:
    # Salt appended (with a per-rule salt) to every hash. Required whenever
    # a "hash" rule actually runs; unset ⇒ the API returns a clear 400
    # instead of hashing without a global salt.
    masking_hash_salt: str | None
    # SQLite file used *only* for rule templates. Source JSON never lands here.
    db_path: str
    # TCP port the container listens on (set via Dockerfile/compose).
    host: str
    port: int
    # Hard cap on pasted payload size to protect local memory.
    max_body_bytes: int


def get_settings() -> Settings:
    return Settings(
        masking_hash_salt=_get("MASKING_HASH_SALT"),
        db_path=_get("SQLITE_PATH", "/data/masking.db"),
        host=_get("HOST", "0.0.0.0"),
        port=int(_get("PORT", "8000")),
        max_body_bytes=int(_get("MAX_BODY_BYTES", str(10 * 1024 * 1024))),
    )
