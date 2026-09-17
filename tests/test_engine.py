"""脱敏引擎核心语义测试。

可直接运行：python3 tests/test_engine.py
也可用 pytest：pytest tests/
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.masking import Engine, JsonPathInvalid, Rule, is_prefix_path, iter_paths


def make_rules(specs):
    rules = []
    for i, spec in enumerate(specs):
        spec = dict(spec)
        spec.setdefault("id", f"r{i}")
        spec.setdefault("name", spec.get("path", f"r{i}"))
        spec["order"] = i
        rules.append(Rule(**spec))
    return rules


def run(data, specs, salt="test-salt"):
    engine = Engine(make_rules(specs), default_salt=salt)
    return engine.run(data)


# ---------------------------------------------------------------- 路径工具

def test_prefix_path():
    assert is_prefix_path("$.a", "$.a")
    assert is_prefix_path("$.a", "$.a.b")
    assert is_prefix_path("$.a", "$.a[0]")
    assert is_prefix_path("$", "$.anything")
    assert not is_prefix_path("$.a", "$.ab")
    assert not is_prefix_path('$.a["x"]', '$.a["x2"]')
    assert not is_prefix_path("$.a", "$.b")


def test_iter_paths_special_keys():
    data = {"a.b": {"x[0]": 1}}
    paths = [p for p, _ in iter_paths(data)]
    assert '$["a.b"]["x[0]"]' in paths


# ---------------------------------------------------------------- 优先级

def test_first_matching_rule_wins():
    data = {"secret": "abc"}
    masked, report, _ = run(data, [
        {"path": "$.secret", "action": "mask", "priority": 20, "id": "mask1"},
        {"path": "$.secret", "action": "delete", "priority": 10, "id": "del1"},
    ])
    # delete 优先级更高（数值小），先生效
    assert masked == {}
    entry = next(e for e in report if e["path"] == "$.secret")
    assert entry["status"] == "matched" and entry["rule_id"] == "del1"


def test_same_path_only_first_executes():
    data = {"v": "hello"}
    masked, report, _ = run(data, [
        {"path": "$.v", "action": "mask", "priority": 1, "id": "m1", "fixed_length": 3},
        {"path": "$.v", "action": "hash", "priority": 2, "id": "h1"},
    ])
    assert masked["v"] == "***"
    matched = [e for e in report if e["status"] == "matched"]
    assert len(matched) == 1 and matched[0]["rule_id"] == "m1"


def test_tie_break_by_list_order():
    data = {"v": "x"}
    masked, _, _ = run(data, [
        {"path": "$.v", "action": "mask", "priority": 5, "id": "a", "fixed_length": 2},
        {"path": "$.v", "action": "delete", "priority": 5, "id": "b"},
    ])
    assert masked == {"v": "**"}  # 同优先级按列表顺序，先 mask


# ---------------------------------------------------------------- 删除语义

def test_parent_delete_skips_children():
    data = {"user": {"name": "张三", "phone": "138"}, "other": 1}
    masked, report, _ = run(data, [
        {"path": "$.user", "action": "delete", "priority": 1, "id": "del"},
        {"path": "$.user.phone", "action": "hash", "priority": 2, "id": "hash"},
    ])
    assert masked == {"other": 1}
    by_path = {e["path"]: e for e in report}
    assert by_path["$.user"]["status"] == "matched"
    assert by_path["$.user.name"]["status"] == "skipped"
    assert by_path["$.user.phone"]["status"] == "skipped"
    assert by_path["$.other"]["status"] == "unmatched"


def test_delete_multiple_list_items():
    # 规则按顺序作用于“当前结果树”：先删尾部 [3] 不影响 [1] 的下标
    data = {"items": ["a", "b", "c", "d"]}
    masked, _, _ = run(data, [
        {"path": "$.items[3]", "action": "delete", "priority": 1},
        {"path": "$.items[1]", "action": "delete", "priority": 2},
    ])
    assert masked == {"items": ["a", "c"]}


def test_delete_shifts_indices_for_later_rules():
    # 顺序语义：先删 [1] 后，原 [3] 已移位为 [2]，按 [3] 匹配不到任何节点
    data = {"items": ["a", "b", "c", "d"]}
    masked, _, _ = run(data, [
        {"path": "$.items[1]", "action": "delete", "priority": 1},
        {"path": "$.items[3]", "action": "delete", "priority": 2},
    ])
    assert masked == {"items": ["a", "c", "d"]}


def test_delete_root():
    masked, report, _ = run({"a": 1}, [{"path": "$", "action": "delete", "priority": 1}])
    assert masked is None
    assert all(e["status"] in ("matched", "skipped") for e in report)


def test_descendant_delete():
    data = {"a": {"secret": 1, "keep": 2}, "b": {"secret": 3}}
    masked, _, _ = run(data, [{"path": "$..secret", "action": "delete", "priority": 1}])
    assert masked == {"a": {"keep": 2}, "b": {}}


# ---------------------------------------------------------------- 掩码/哈希

def test_mask_fixed_and_keep_length():
    data = {"a": "hello", "b": "world!"}
    masked, _, _ = run(data, [
        {"path": "$.a", "action": "mask", "priority": 1, "fixed_length": 4},
        {"path": "$.b", "action": "mask", "priority": 2, "keep_length": True, "mask_char": "#"},
    ])
    assert masked == {"a": "****", "b": "######"}


def test_hash_deterministic_and_salted():
    data = {"p": "13800001111"}
    m1, _, _ = run(data, [{"path": "$.p", "action": "hash", "priority": 1}], salt="s1")
    m2, _, _ = run(data, [{"path": "$.p", "action": "hash", "priority": 1}], salt="s1")
    m3, _, _ = run(data, [{"path": "$.p", "action": "hash", "priority": 1}], salt="s2")
    assert m1 == m2 and m1 != m3
    assert len(m1["p"]) == 16


# ---------------------------------------------------------------- 稳定编号

def test_stable_numbering():
    data = {"users": [{"n": "张三"}, {"n": "李四"}, {"n": "张三"}]}
    masked, _, _ = run(data, [
        {"path": "$.users[*].n", "action": "number", "priority": 1, "prefix": "U"},
    ])
    names = [u["n"] for u in masked["users"]]
    assert names == ["U-0001", "U-0002", "U-0001"]


def test_numbering_per_rule_independent():
    data = {"a": "x", "b": "x"}
    masked, _, _ = run(data, [
        {"path": "$.a", "action": "number", "priority": 1, "id": "r1", "prefix": "A"},
        {"path": "$.b", "action": "number", "priority": 2, "id": "r2", "prefix": "B"},
    ])
    assert masked == {"a": "A-0001", "b": "B-0001"}


def test_repeat_run_identical():
    data = {"list": [{"v": "a"}, {"v": "b"}, {"v": "a"}, {"v": "c"}]}
    specs = [{"path": "$.list[*].v", "action": "number", "priority": 1, "prefix": "N"}]
    m1, _, _ = run(data, specs)
    m2, _, _ = run(data, specs)
    assert m1 == m2


# ---------------------------------------------------------------- 报告/审计

def test_report_covers_all_paths():
    data = {"x": {"y": 1}, "z": [1, 2]}
    _, report, _ = run(data, [{"path": "$.x.y", "action": "mask", "priority": 1}])
    paths = {e["path"] for e in report}
    assert paths == {"$", "$.x", "$.x.y", "$.z", "$.z[0]", "$.z[1]"}
    unmatched = [e for e in report if e["status"] == "unmatched"]
    assert any(e["path"] == "$.z[0]" for e in unmatched)


def test_audit_has_no_original_values():
    data = {"phone": "13800001111", "keep": "公开信息"}
    _, _, audit = run(data, [
        {"path": "$.phone", "action": "hash", "priority": 1},
    ])
    blob = str(audit)
    assert "13800001111" not in blob
    assert "公开信息" not in blob  # 未命中路径的原值也不得出现在审计里
    assert all("original" not in e for e in audit)


def test_invalid_jsonpath():
    try:
        run({"a": 1}, [{"path": "$.[", "action": "mask", "priority": 1}])
    except JsonPathInvalid:
        return
    raise AssertionError("应当抛出 JsonPathInvalid")


def test_disabled_rule_ignored():
    data = {"v": "x"}
    masked, _, _ = run(data, [
        {"path": "$.v", "action": "delete", "priority": 1, "enabled": False},
    ])
    assert masked == {"v": "x"}


ALL_TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    failed = 0
    for t in ALL_TESTS:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as exc:
            failed += 1
            print(f"FAIL {t.__name__}: {exc}")
    print(f"\n{len(ALL_TESTS) - failed}/{len(ALL_TESTS)} 通过")
    sys.exit(1 if failed else 0)
