#!/usr/bin/env bash
# Container startup: validate env, prepare data dir, launch the API.
set -euo pipefail

: "${PORT:=8000}"
: "${SQLITE_PATH:=/data/masking.db}"

mkdir -p "$(dirname "$SQLITE_PATH")"

if [ -z "${MASKING_HASH_SALT:-}" ]; then
  echo "[entrypoint] WARNING: MASKING_HASH_SALT 未设置；hash（带盐哈希）规则执行时将返回 400。" >&2
fi

echo "[entrypoint] starting on 0.0.0.0:${PORT}, db=${SQLITE_PATH}"
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}"
