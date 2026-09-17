"""Masking engine.

Semantics (mirrored in README):

* Rules are sorted by ``(priority, original order)`` — smaller priority
  value first.
* A JSONPath expression may match several concrete paths. The first rule
  (in priority order) that matches a path *governs* that path; later rules
  matching the same path are recorded as ``skipped`` ("同一路径只执行首条").
* Once a rule governs a path it governs the whole subtree: descendant
  paths matched by other rules are ``blocked``.  This covers "父节点被删除
  后不再处理子路径" and also the structurally identical case where the
  ancestor value is replaced wholesale (mask / hash / number produce a
  scalar in place of an object/array).
* Numbering counters live **inside one rule execution**: values are
  numbered in DFS first-seen order; equal values get equal numbers,
  different values get different numbers.  Re-running with the same input
  and rule set yields the same output. Blocked matches do not consume
  numbers.
* The engine never logs anything and returns values only in its result
  structure; the audit builder (``build_audit``) strips every value.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from jsonpath_ng.ext import parse as jsonpath_parse
from jsonpath_ng.jsonpath import Fields, Index, Root, This

ACTIONS = ("delete", "mask", "hash", "number")
_SAFE_KEY = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


class EngineError(ValueError):
    """400-class error with a message safe to show to the user."""


class HashSaltMissing(EngineError):
    def __init__(self) -> None:
        super().__init__(
            "存在 hash（带盐哈希）规则但未配置全局盐 MASKING_HASH_SALT；"
            "请在环境变量中设置后重试。"
        )


# --------------------------------------------------------------------------- #
# Path helpers
# --------------------------------------------------------------------------- #

Path = tuple[Any, ...]

_MISSING = object()


def format_path(path: Path) -> str:
    """Canonical bracket path, e.g. ``$["a"][0]``."""
    out = "$"
    for part in path:
        if isinstance(part, str):
            out += "[" + json.dumps(part, ensure_ascii=False) + "]"
        else:
            out += f"[{part}]"
    return out


def display_path(path: Path) -> str:
    """Human-friendly path, e.g. ``$.a[0]`` (falls back to brackets)."""
    out = "$"
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        elif isinstance(part, str) and _SAFE_KEY.match(part):
            out += "." + part
        elif isinstance(part, str):
            out += "[" + json.dumps(part, ensure_ascii=False) + "]"
        else:  # pragma: no cover - JSON keys are str|int
            out += "[" + json.dumps(part, ensure_ascii=False) + "]"
    return out


def _datum_path(datum: Any) -> Path | None:
    """Derive the concrete path tuple of a jsonpath-ng datum.

    ``datum.path`` is the final step; the ``context`` chain holds ancestors.
    """
    steps: list[Any] = []

    def consume(step: Any) -> bool:
        if isinstance(step, (Root, This)):
            return True  # root marker: no path component
        if isinstance(step, Fields):
            steps.append(step.fields[0])
            return True
        if isinstance(step, Index):
            steps.append(step.index)
            return True
        return False

    if not consume(datum.path):
        return None
    ctx = datum.context
    while ctx is not None:
        if not consume(ctx.path):
            return None
        ctx = ctx.context
    return tuple(reversed(steps))


def walk(value: Any, path: Path = ()) -> Iterator[tuple[Path, Any]]:
    """DFS first-seen traversal; objects follow insertion order."""
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, path + (index,))


def _reach(root: Any, path: Path) -> Any:
    cur = root
    for part in path:
        if isinstance(cur, dict) and isinstance(part, str) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and isinstance(part, int) and -len(cur) <= part < len(cur):
            cur = cur[part]
        else:
            return _MISSING
    return cur


# --------------------------------------------------------------------------- #
# Rule model & parameter validation
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MaskParams:
    keep_first: int = 0
    keep_last: int = 0
    mask_char: str = "*"
    mask_length: int | None = None  # None ⇒ same length as hidden chars


@dataclass(frozen=True)
class HashParams:
    salt: str = ""
    length: int = 64  # 1..64 hex chars; 64 ⇒ full sha256


@dataclass(frozen=True)
class NumberParams:
    prefix: str = ""
    suffix: str = ""
    padding: int = 0   # 0 ⇒ no padding
    start: int = 1


@dataclass
class CompiledRule:
    id: str
    name: str
    path_expr: str
    action: str
    priority: int
    params: MaskParams | HashParams | NumberParams
    expr: Any = None


def _as_int(params: dict, key: str, default: int, minimum: int, maximum: int) -> int:
    value = params.get(key, default)
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int):
        raise EngineError(f"规则参数 {key} 必须是整数")
    if not (minimum <= value <= maximum):
        raise EngineError(f"规则参数 {key} 必须在 {minimum}..{maximum} 之间")
    return value


def _as_str(params: dict, key: str, default: str) -> str:
    value = params.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, str):
        raise EngineError(f"规则参数 {key} 必须是字符串")
    return value


def compile_rule(rule: dict) -> CompiledRule:
    rule_id = str(rule.get("id") or rule.get("name") or "rule")
    name = str(rule.get("name") or rule_id)
    action = rule.get("action")
    if action not in ACTIONS:
        raise EngineError(f"规则 {name}: 未知动作 {action!r}")
    try:
        priority = int(rule.get("priority", 100))
    except (TypeError, ValueError):
        raise EngineError(f"规则 {name}: priority 必须是整数")
    path_expr = rule.get("path")
    if not isinstance(path_expr, str) or not path_expr.strip():
        raise EngineError(f"规则 {name}: JSONPath 不能为空")
    try:
        expr = jsonpath_parse(path_expr)
    except Exception as exc:  # jsonpath_ng raises various parse errors
        raise EngineError(f"规则 {name}: JSONPath 语法错误 — {exc}") from exc

    raw_params = rule.get("params") or {}
    if not isinstance(raw_params, dict):
        raise EngineError(f"规则 {name}: params 必须是对象")

    if action == "mask":
        keep_first = _as_int(raw_params, "keep_first", 0, 0, 1024)
        keep_last = _as_int(raw_params, "keep_last", 0, 0, 1024)
        mask_char = _as_str(raw_params, "mask_char", "*")
        if not mask_char:
            raise EngineError(f"规则 {name}: mask_char 不能为空")
        mask_char = mask_char[0]
        mask_length_raw = raw_params.get("mask_length")
        mask_length = None
        if mask_length_raw is not None:
            mask_length = _as_int(raw_params, "mask_length", 0, 0, 4096)
        params: Any = MaskParams(keep_first, keep_last, mask_char, mask_length)
    elif action == "hash":
        salt = _as_str(raw_params, "salt", "")
        length = _as_int(raw_params, "length", 64, 1, 64)
        params = HashParams(salt, length)
    elif action == "number":
        prefix = _as_str(raw_params, "prefix", "")
        suffix = _as_str(raw_params, "suffix", "")
        padding = _as_int(raw_params, "padding", 0, 0, 20)
        start = _as_int(raw_params, "start", 1, 0, 10**9)
        params = NumberParams(prefix, suffix, padding, start)
    else:
        params = None

    return CompiledRule(rule_id, name, path_expr, action, priority, params, expr)


# --------------------------------------------------------------------------- #
# Value transforms
# --------------------------------------------------------------------------- #


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _value_key(value: Any) -> str:
    # Type tag prevents 1 / "1" / true collisions in numbering maps.
    return type(value).__name__ + ":" + canonical_json(value)


def apply_mask(value: Any, p: MaskParams) -> str:
    text = value if isinstance(value, str) else canonical_json(value)
    n = len(text)
    kf = min(p.keep_first, n)
    kl = min(p.keep_last, n - kf)
    hidden = n - kf - kl
    if hidden <= 0 and p.mask_length is None:
        return text
    pad_len = p.mask_length if p.mask_length is not None else max(hidden, 0)
    head = text[:kf]
    tail = text[n - kl:] if kl else ""
    return head + (p.mask_char * pad_len) + tail


def apply_hash(value: Any, global_salt: str, p: HashParams) -> str:
    digest = hashlib.sha256()
    digest.update(global_salt.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(p.salt.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(canonical_json(value).encode("utf-8"))
    return digest.hexdigest()[: p.length]


def format_number(index: int, p: NumberParams) -> int | str:
    num = p.start + index
    if not p.prefix and not p.suffix and p.padding == 0:
        return num
    width = max(p.padding, len(str(p.start)))
    return f"{p.prefix}{str(num).zfill(width)}{p.suffix}"


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #


@dataclass
class _RuleStat:
    rule: CompiledRule
    applied: int = 0
    skipped: int = 0
    blocked: int = 0
    matched: int = 0


@dataclass
class MaskResult:
    document: Any
    groups: list[dict]
    rule_stats: list[dict]
    rule_errors: list[dict]
    summary: dict = field(default_factory=dict)


def run_masking(
    document: Any,
    rules: list[dict],
    global_hash_salt: str | None,
) -> MaskResult:
    # Compile rules; bad rules are reported and excluded from matching.
    compiled: list[CompiledRule] = []
    rule_errors: list[dict] = []
    for raw in rules:
        if not raw.get("enabled", True):
            continue
        try:
            compiled.append(compile_rule(raw))
        except EngineError as exc:
            rule_errors.append(
                {
                    "rule_id": str(raw.get("id") or raw.get("name") or "rule"),
                    "rule_name": str(raw.get("name") or raw.get("id") or "rule"),
                    "error": str(exc),
                }
            )
    # Python sort is stable, so equal priorities keep input order.
    compiled.sort(key=lambda r: r.priority)

    # First-seen path order drives both determinism and numbering.
    all_paths: list[Path] = []
    values: dict[Path, Any] = {}
    for path, value in walk(document):
        all_paths.append(path)
        values[path] = value

    # Match every rule against every datum it returns.
    matched_by: dict[Path, list[CompiledRule]] = {}
    for rule in compiled:
        try:
            data = rule.expr.find(document)
        except Exception as exc:  # pragma: no cover - defensive
            rule_errors.append(
                {"rule_id": rule.id, "rule_name": rule.name, "error": f"匹配失败：{exc}"}
            )
            continue
        seen: set[Path] = set()
        for datum in data:
            path = _datum_path(datum)
            if path is None or path in seen:
                continue
            seen.add(path)
            matched_by.setdefault(path, []).append(rule)

    # First matching rule per path governs it.
    winner: dict[Path, CompiledRule] = {
        path: hits[0] for path, hits in matched_by.items()
    }

    # Ancestor claim blocks descendants (deleted or replaced subtree).
    def nearest_claimed_ancestor(path: Path) -> tuple[Path, CompiledRule] | None:
        for depth in range(len(path) - 1, -1, -1):
            ancestor = path[:depth]
            if ancestor in winner and ancestor != path:
                return ancestor, winner[ancestor]
        return None

    blocked: dict[Path, tuple[Path, CompiledRule]] = {}
    for path, rule in winner.items():
        claim = nearest_claimed_ancestor(path)
        if claim is not None:
            blocked[path] = claim

    # A hash rule that actually applies needs the global salt.
    if global_hash_salt is None:
        for path, rule in winner.items():
            if rule.action == "hash" and path not in blocked:
                raise HashSaltMissing()

    # Stable numbering: per rule, DFS first-seen, same value ⇒ same number.
    counters: dict[str, dict[str, int]] = {}
    for path in all_paths:
        rule = winner.get(path)
        if rule is None or path in blocked or rule.action != "number":
            continue
        mapping = counters.setdefault(rule.id, {})
        key = _value_key(values[path])
        if key not in mapping:
            mapping[key] = len(mapping)  # 0-based; start offset applied later

    # Apply to a deep copy. All governed paths are pairwise disjoint
    # (ancestor claims suppress descendants), so parents always survive.
    result_doc: Any = copy.deepcopy(document)

    # 1) compute transformed values
    transformed: dict[Path, Any] = {}
    for path, rule in winner.items():
        if path in blocked:
            continue
        value = values[path]
        if rule.action == "mask":
            transformed[path] = apply_mask(value, rule.params)
        elif rule.action == "hash":
            transformed[path] = apply_hash(value, global_hash_salt, rule.params)
        elif rule.action == "number":
            number_index = counters[rule.id][_value_key(value)]
            transformed[path] = format_number(number_index, rule.params)
        # delete handled below

    # 2) deletions — resolve parents on the copy first, then mutate.
    delete_paths = [
        p for p, r in winner.items() if r.action == "delete" and p not in blocked
    ]
    if () in delete_paths:
        # Deleting the root document.
        result_doc = None
        delete_paths.remove(())

    pending: list[tuple[Any, Any]] = []
    for path in delete_paths:
        parent = _reach(result_doc, path[:-1])
        if parent is _MISSING:
            continue
        pending.append((parent, path[-1], len(path)))

    def _delete_order(item: tuple[Any, Any, int]) -> tuple[int, int, int]:
        _parent, key, depth = item
        # Deeper first; within one array, higher index first. Dict keys are
        # unordered relative to indices, never comparable with them.
        return (-depth, 0 if isinstance(key, int) else 1, -key if isinstance(key, int) else 0)

    for parent, key, _depth in sorted(pending, key=_delete_order):
        if isinstance(parent, list) and isinstance(key, int):
            if -len(parent) <= key < len(parent):
                del parent[key]
        elif isinstance(parent, dict):
            parent.pop(key, None)

    # 3) replacements
    for path, new_value in transformed.items():
        parent = _reach(result_doc, path[:-1])
        if parent is _MISSING:
            continue
        key = path[-1]
        if isinstance(parent, dict):
            parent[key] = new_value
        elif isinstance(parent, list) and isinstance(key, int) and -len(parent) <= key < len(parent):
            parent[key] = new_value

    # ------------------------------------------------------------------ #
    # Report groups
    # ------------------------------------------------------------------ #
    stats: dict[str, _RuleStat] = {r.id: _RuleStat(r) for r in compiled}
    groups: list[dict] = []

    n_deleted = n_changed = n_blocked = n_unmatched = n_skipped = 0

    for path in all_paths:
        hits = matched_by.get(path, [])
        win = winner.get(path)
        claim = blocked.get(path)
        entries: list[dict] = []

        for rule in hits:
            if rule is win and claim is None:
                status = "applied"
                reason = None
                stats[rule.id].applied += 1
            elif rule is win and claim is not None:
                status = "blocked"
                reason = f"祖先路径 {display_path(claim[0])} 已被规则「{claim[1].name}」处理，子路径不再执行"
                stats[rule.id].blocked += 1
            else:
                status = "skipped"
                reason = f"同一路径只执行首条规则，已由规则「{win.name}」命中"
                stats[rule.id].skipped += 1
            stats[rule.id].matched += 1
            entries.append(
                {
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "action": rule.action,
                    "priority": rule.priority,
                    "status": status,
                    "reason": reason,
                }
            )

        unmatched = [
            {"rule_id": r.id, "rule_name": r.name, "action": r.action}
            for r in compiled
            if r not in hits
        ]

        if win is not None and claim is None:
            state = win.action
            result_value = transformed.get(path, None) if win.action != "delete" else None
            n_changed += 1 if win.action != "delete" else 0
            if win.action == "delete":
                n_deleted += 1
        elif win is not None and claim is not None:
            state = "blocked"
            result_value = None
            n_blocked += 1
        else:
            state = "unmatched"
            result_value = values[path]
            n_unmatched += 1
        n_skipped += sum(1 for e in entries if e["status"] == "skipped")

        groups.append(
            {
                "path": display_path(path),
                "canonical_path": format_path(path),
                "depth": len(path),
                "state": state,
                "original": values[path],
                "result": result_value,
                "winner_rule_id": win.id if win else None,
                "entries": entries,
                "unmatched_rules": unmatched,
            }
        )

    rule_stats = [
        {
            "rule_id": s.rule.id,
            "rule_name": s.rule.name,
            "action": s.rule.action,
            "priority": s.rule.priority,
            "path": s.rule.path_expr,
            "matched": s.matched,
            "applied": s.applied,
            "skipped": s.skipped,
            "blocked": s.blocked,
            "never_matched": s.matched == 0,
        }
        for s in stats.values()
    ]

    summary = {
        "paths_total": len(all_paths),
        "deleted": n_deleted,
        "changed": n_changed,
        "blocked": n_blocked,
        "skipped": n_skipped,
        "unmatched": n_unmatched,
        "rules": len(compiled),
        "rule_errors": len(rule_errors),
    }

    return MaskResult(result_doc, groups, rule_stats, rule_errors, summary)


def build_audit(result: MaskResult) -> dict:
    """Audit checklist — contains paths, rule names and states only.

    No original values, no result values, no salts.
    """
    return {
        "summary": result.summary,
        "rule_errors": result.rule_errors,
        "rule_stats": result.rule_stats,
        "paths": [
            {
                "path": g["path"],
                "canonical_path": g["canonical_path"],
                "depth": g["depth"],
                "state": g["state"],
                "winner_rule_id": g["winner_rule_id"],
                "entries": g["entries"],
                "unmatched_rule_ids": [u["rule_id"] for u in g["unmatched_rules"]],
            }
            for g in result.groups
        ],
    }
