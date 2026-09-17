"""FastAPI 入口：JSON 数据脱敏工作台。

安全设计：
- /api/preview 全程内存处理，响应即用即弃，不写数据库、不写日志、不写文件。
- SQLite 仅保存规则模板（见 db.py）。
- 审计清单（audit）由引擎生成，不含原值；含原值的 report 仅用于页面预览。
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .db import TemplateStore
from .masking import Engine, JsonPathInvalid, Rule
from .schemas import PreviewRequest, PreviewResponse, TemplateIn

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

MASK_SALT = os.environ.get("MASK_SALT", "local-dev-salt")
DATA_DIR = os.environ.get("DATA_DIR", str(BASE_DIR.parent / "data"))

app = FastAPI(title="JSON 数据脱敏工作台", version="1.0.0")
store = TemplateStore(os.path.join(DATA_DIR, "templates.db"))


def _to_rules(req: PreviewRequest | TemplateIn) -> list[Rule]:
    rules = []
    for i, r in enumerate(req.rules):
        rules.append(Rule(
            id=r.id or f"rule-{i + 1}",
            name=r.name or r.path,
            path=r.path,
            action=r.action,
            priority=r.priority,
            enabled=r.enabled,
            order=i,
            mask_char=r.mask_char,
            keep_length=r.keep_length,
            fixed_length=r.fixed_length,
            salt=r.salt,
            hash_length=r.hash_length,
            prefix=r.prefix,
        ))
    return rules


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/preview", response_model=PreviewResponse)
def preview(req: PreviewRequest):
    """脱敏预览：内存计算，绝不持久化请求数据。"""
    engine = Engine(_to_rules(req), default_salt=MASK_SALT)
    try:
        masked, report, audit = engine.run(req.data)
    except JsonPathInvalid as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"masked": masked, "report": report, "audit": audit}


# -- 规则模板（SQLite 仅存模板，不存数据） ------------------------------------

@app.get("/api/templates")
def list_templates():
    return store.list()


@app.get("/api/templates/{template_id}")
def get_template(template_id: str):
    tpl = store.get(template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="模板不存在")
    return tpl


@app.post("/api/templates", status_code=201)
def create_template(tpl: TemplateIn):
    rules = [r.model_dump() for r in tpl.rules]
    return store.create(tpl.name, rules)


@app.put("/api/templates/{template_id}")
def update_template(template_id: str, tpl: TemplateIn):
    rules = [r.model_dump() for r in tpl.rules]
    out = store.update(template_id, tpl.name, rules)
    if out is None:
        raise HTTPException(status_code=404, detail="模板不存在")
    return out


@app.delete("/api/templates/{template_id}")
def delete_template(template_id: str):
    if not store.delete(template_id):
        raise HTTPException(status_code=404, detail="模板不存在")
    return {"deleted": True}


# -- 前端静态资源 -------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
