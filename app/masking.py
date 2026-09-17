"""JSON 数据脱敏引擎。

核心语义：
- 规则按 (priority, 列表顺序) 排序，逐条作用于“当前结果树”。
- 每条规则用 JSONPath 匹配若干路径；同一路径只执行第一条命中的规则，
  后续规则再匹配到该路径（或其子孙路径）时跳过。
- 父节点被删除后，其所有子孙路径视为已消费，不再处理。
- 稳定编号：每条规则独立维护 值->编号 映射，按文档中首次出现顺序分配，
  同值同号、异值异号；同一输入重复运行结果一致。

安全约束：引擎只在内存中处理数据，不写库、不写日志。
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from jsonpath_ng.ext import parse as parse_jsonpath

ROOT = "$"
_DELETE = object()  # 删除哨兵

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class JsonPathInvalid(ValueError):
    """JSONPath 表达式无法解析。"""


# ---------------------------------------------------------------------------
# 规范路径工具：形如 $.a.b[0]["特殊 key"]
# ---------------------------------------------------------------------------

def join_key(path: str, key: str) -> str:
    if _IDENT_RE.match(key):
        return f"{path}.{key}"
    return f"{path}[{json.dumps(key, ensure_ascii=False)}]"


def join_index(path: str, index: int) -> str:
    return f"{path}[{index}]"


def iter_paths(obj: Any, path: str = ROOT) -> Iterator[tuple[str, Any]]:
    """按文档顺序（父先于子）产出 (规范路径, 值)。"""
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from iter_paths(v, join_key(path, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from iter_paths(v, join_index(path, i))


def is_prefix_path(ancestor: str, path: str) -> bool:
    """ancestor 是否为 path 的祖先（或相同）路径。"""
    if ancestor == path:
        return True
    if not path.startswith(ancestor):
        return False
    if ancestor == ROOT:
        return True
    # 边界必须是段分隔符，避免 $.a 误判为 $.ab 的祖先
    return path[len(ancestor)] in ".["


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonical_of(node: Any) -> str:
    """把 jsonpath-ng 的路径对象转成规范路径字符串。

    注意：匹配结果的 full_path 链最左端通常是 Fields/Index（Root 被省略），
    仅当表达式为 $ 本身时才出现 Root 节点。
    """
    from jsonpath_ng import Child, Fields, Index, Root

    if isinstance(node, Root):
        return ROOT
    if isinstance(node, Fields):
        out = ROOT
        for f in node.fields:
            out = join_key(out, f)
        return out
    if isinstance(node, Index):
        return join_index(ROOT, node.indices[0])
    if isinstance(node, Child):
        left = _canonical_of(node.left)
        right = node.right
        if isinstance(right, Fields):
            for f in right.fields:
                left = join_key(left, f)
            return left
        if isinstance(right, Index):
            return join_index(left, right.indices[0])
    raise JsonPathInvalid(f"不支持的 JSONPath 节点: {node!r}")


# ---------------------------------------------------------------------------
# 规则与引擎
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    name: str
    path: str
    action: str  # delete | mask | hash | number
    priority: int = 100
    enabled: bool = True
    order: int = 0  # 列表顺序，作为 priority 的并列决胜
    # mask 参数
    mask_char: str = "*"
    keep_length: bool = False
    fixed_length: int = 8
    # hash 参数
    salt: Optional[str] = None
    hash_length: int = 16
    # number 参数
    prefix: str = "ID"


class Engine:
    def __init__(self, rules: list[Rule], default_salt: str = ""):
        self.rules = sorted(
            (r for r in rules if r.enabled),
            key=lambda r: (r.priority, r.order),
        )
        self.rules_by_id = {r.id: r for r in self.rules}
        self.default_salt = default_salt
        self._expr_cache: dict[str, Any] = {}
        # path -> rule_id（仅记录被规则直接消费的路径）
        self.consumed_by: dict[str, str] = {}
        # path -> 替换后的值（delete 时为 None）
        self.result_by_path: dict[str, Any] = {}
        # 稳定编号状态：rule_id -> {值的规范JSON: 编号}
        self._number_maps: dict[str, dict[str, int]] = {}

    # -- 编译 JSONPath ------------------------------------------------------
    def _expr(self, path: str):
        if path not in self._expr_cache:
            try:
                self._expr_cache[path] = parse_jsonpath(path)
            except Exception as exc:  # jsonpath-ng 抛出的异常类型较多
                raise JsonPathInvalid(f"JSONPath 无法解析: {path!r} ({exc})") from exc
        return self._expr_cache[path]

    # -- 消费判定 -----------------------------------------------------------
    def covering_rule(self, path: str) -> Optional[tuple[str, bool]]:
        """返回 (rule_id, exact)；exact=False 表示被祖先路径覆盖。"""
        rid = self.consumed_by.get(path)
        if rid is not None:
            return rid, True
        for consumed, rid in self.consumed_by.items():
            if is_prefix_path(consumed, path):
                return rid, False
        return None

    # -- 值变换 -------------------------------------------------------------
    def _compute(self, rule: Rule, value: Any) -> Any:
        if rule.action == "mask":
            ch = (rule.mask_char or "*")[0]
            if rule.keep_length and isinstance(value, str):
                return ch * len(value)
            return ch * max(1, int(rule.fixed_length))
        if rule.action == "hash":
            salt = rule.salt if rule.salt is not None else self.default_salt
            digest = hashlib.sha256((salt + canonical_json(value)).encode("utf-8")).hexdigest()
            return digest[: max(4, int(rule.hash_length))]
        if rule.action == "number":
            mapping = self._number_maps.setdefault(rule.id, {})
            key = canonical_json(value)
            if key not in mapping:
                mapping[key] = len(mapping) + 1
            return f"{rule.prefix}-{mapping[key]:04d}"
        raise ValueError(f"未知动作: {rule.action}")

    # -- 单规则应用 ---------------------------------------------------------
    def _transform(self, node: Any, path: str, rule: Rule,
                   targets: set[str], applied: list[tuple[str, Any, Any]]) -> Any:
        """单趟重建子树；命中目标路径则替换/删除，返回新值或 _DELETE。"""
        if path in targets:
            if rule.action == "delete":
                applied.append((path, node, None))
                return _DELETE
            new_value = self._compute(rule, node)
            applied.append((path, node, new_value))
            return new_value
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                r = self._transform(v, join_key(path, k), rule, targets, applied)
                if r is not _DELETE:
                    out[k] = r
            return out
        if isinstance(node, list):
            out = []
            for i, v in enumerate(node):
                r = self._transform(v, join_index(path, i), rule, targets, applied)
                if r is not _DELETE:
                    out.append(r)
            return out
        return node

    def apply_rule(self, rule: Rule, data: Any) -> Any:
        expr = self._expr(rule.path)
        targets: set[str] = set()
        for m in expr.find(data):
            p = _canonical_of(m.full_path)
            if p in targets:
                continue
            if self.covering_rule(p) is not None:
                continue  # 已被更高优先级规则消费
            targets.add(p)
        if not targets:
            return data
        applied: list[tuple[str, Any, Any]] = []
        new_data = self._transform(data, ROOT, rule, targets, applied)
        if new_data is _DELETE:
            new_data = None
        for p, _orig, res in applied:
            self.consumed_by[p] = rule.id
            self.result_by_path[p] = res
        return new_data

    # -- 主流程 -------------------------------------------------------------
    def run(self, data: Any) -> tuple[Any, list[dict], list[dict]]:
        original = copy.deepcopy(data)
        result = copy.deepcopy(data)
        for rule in self.rules:
            result = self.apply_rule(rule, result)
        report = self._build_report(original)
        # 审计清单绝不包含原值：仅保留 hash/number 的脱敏产物（伪编号/哈希值），
        # 未命中、被跳过、被删除及掩码条目一律不带结果值。
        audit = []
        for e in report:
            safe = {k: e[k] for k in ("path", "status", "rule_id", "rule_name", "action")}
            if e["status"] == "matched" and e["action"] in ("hash", "number"):
                safe["result"] = e["result"]
            else:
                safe["result"] = None
            audit.append(safe)
        return result, report, audit

    def _build_report(self, original: Any) -> list[dict]:
        entries = []
        for path, value in iter_paths(original):
            covering = self.covering_rule(path)
            if covering is None:
                entries.append({
                    "path": path, "status": "unmatched",
                    "rule_id": None, "rule_name": None, "action": None,
                    "original": value, "result": value,
                })
                continue
            rid, exact = covering
            rule = self.rules_by_id[rid]
            if exact:
                status, res = "matched", self.result_by_path.get(path)
            else:
                status, res = "skipped", None  # 祖先被删除/整体替换
            entries.append({
                "path": path, "status": status,
                "rule_id": rule.id, "rule_name": rule.name, "action": rule.action,
                "original": value, "result": res,
            })
        return entries
