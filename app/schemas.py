"""API 请求/响应模型。"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Action = Literal["delete", "mask", "hash", "number"]


class RuleIn(BaseModel):
    id: Optional[str] = None
    name: str = ""
    path: str
    action: Action
    priority: int = 100
    enabled: bool = True
    # mask
    mask_char: str = "*"
    keep_length: bool = False
    fixed_length: int = Field(default=8, ge=1, le=128)
    # hash
    salt: Optional[str] = None
    hash_length: int = Field(default=16, ge=4, le=64)
    # number
    prefix: str = "ID"


class PreviewRequest(BaseModel):
    data: Any
    rules: list[RuleIn] = []


class ReportEntry(BaseModel):
    path: str
    status: Literal["matched", "unmatched", "skipped"]
    rule_id: Optional[str]
    rule_name: Optional[str]
    action: Optional[Action]
    original: Any = None
    result: Any = None


class PreviewResponse(BaseModel):
    masked: Any
    report: list[ReportEntry]  # 含原值，仅用于页面预览，不落盘
    audit: list[dict]          # 不含原值，可安全导出


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    rules: list[RuleIn] = []


class TemplateOut(BaseModel):
    id: str
    name: str
    rules: list[RuleIn]
    created_at: str
    updated_at: str


class TemplateSummary(BaseModel):
    id: str
    name: str
    rule_count: int
    created_at: str
    updated_at: str
