"""Pydantic models for request bodies (templates only — masking requests are
parsed as plain JSON so the source data never touches validation logs)."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Action = Literal["delete", "mask", "hash", "number"]


class RuleIn(BaseModel):
    id: str | None = None
    name: str = Field(min_length=1, max_length=100)
    path: str = Field(min_length=1, max_length=1000)
    action: Action
    priority: int = 100
    enabled: bool = True
    params: dict[str, Any] = Field(default_factory=dict)


class MaskRequest(BaseModel):
    document: Any
    rules: list[RuleIn] = Field(default_factory=list)

    @field_validator("document")
    @classmethod
    def _document_must_be_json(cls, v: Any) -> Any:
        if not isinstance(v, (dict, list)):
            raise ValueError("document 必须是 JSON 对象或数组（顶层）")
        return v


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    rules: list[RuleIn] = Field(default_factory=list)
