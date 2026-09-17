"""FastAPI application for the local JSON masking workbench."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from . import db
from .config import get_settings
from .engine import EngineError, build_audit, run_masking
from .schemas import MaskRequest, TemplateIn

logger = logging.getLogger("masking")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="JSON 数据脱敏工作台", version="1.0.0")


@app.on_event("startup")
def _startup() -> None:
    app.state.db = db.connect(settings.db_path)
    logger.info("started; template database ready at %s", settings.db_path)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _rules_as_dicts(rules: list[Any]) -> list[dict]:
    return [r.model_dump() for r in rules]


async def _parse_mask_request(request: Request) -> MaskRequest:
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="请求体不是合法 JSON") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 {document, rules} 对象")
    try:
        return MaskRequest(**body)
    except ValidationError as exc:
        # Keep error payload JSON-safe and free of request input values.
        safe_errors = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")}
            for e in exc.errors()
        ]
        raise HTTPException(status_code=422, detail=safe_errors) from exc


def _run(document: Any, raw_rules: list[dict]) -> Any:
    try:
        return run_masking(document, raw_rules, settings.masking_hash_salt)
    except EngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _request_too_large(request: Request) -> JSONResponse | None:
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > settings.max_body_bytes:
        return JSONResponse(
            status_code=413,
            content={
                "detail": f"请求体超过 {settings.max_body_bytes} 字节限制（MAX_BODY_BYTES）"
            },
        )
    return None


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "hash_salt_configured": settings.masking_hash_salt is not None}


@app.post("/api/mask/preview")
async def preview(request: Request) -> dict:
    too_large = _request_too_large(request)
    if too_large:
        return too_large  # type: ignore[return-value]
    parsed = await _parse_mask_request(request)
    result = _run(parsed.document, _rules_as_dicts(parsed.rules))
    return {
        "result": result.document,
        "groups": result.groups,
        "rule_stats": result.rule_stats,
        "rule_errors": result.rule_errors,
        "summary": result.summary,
        "hash_salt_configured": settings.masking_hash_salt is not None,
    }


@app.post("/api/mask/export")
async def export_masked(request: Request) -> JSONResponse:
    too_large = _request_too_large(request)
    if too_large:
        return too_large  # type: ignore[return-value]
    parsed = await _parse_mask_request(request)
    result = _run(parsed.document, _rules_as_dicts(parsed.rules))
    return JSONResponse(
        result.document,
        headers={"Content-Disposition": 'attachment; filename="masked.json"'},
    )


@app.post("/api/mask/audit")
async def export_audit(request: Request) -> dict:
    too_large = _request_too_large(request)
    if too_large:
        return too_large  # type: ignore[return-value]
    parsed = await _parse_mask_request(request)
    result = _run(parsed.document, _rules_as_dicts(parsed.rules))
    audit = build_audit(result)
    audit["export_kind"] = "audit"
    return audit


# ---------------- templates (only thing that touches SQLite) --------------- #


@app.get("/api/templates")
def templates_list() -> list[dict]:
    return db.list_templates(app.state.db)


@app.post("/api/templates", status_code=201)
def templates_create(payload: TemplateIn) -> dict:
    try:
        return db.create_template(
            app.state.db,
            payload.name,
            payload.description,
            _rules_as_dicts(payload.rules),
        )
    except Exception as exc:  # unique name etc.
        app.state.db.rollback()
        raise HTTPException(status_code=409, detail=f"保存失败：{exc}") from exc


@app.put("/api/templates/{template_id}")
def templates_update(template_id: str, payload: TemplateIn) -> dict:
    updated = db.update_template(
        app.state.db,
        template_id,
        payload.name,
        payload.description,
        _rules_as_dicts(payload.rules),
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="模板不存在")
    return updated


@app.delete("/api/templates/{template_id}", status_code=204)
def templates_delete(template_id: str) -> Response:
    if not db.delete_template(app.state.db, template_id):
        raise HTTPException(status_code=404, detail="模板不存在")
    return Response(status_code=204)


# --------------------------------------------------------------------------- #
# Frontend
# --------------------------------------------------------------------------- #


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
