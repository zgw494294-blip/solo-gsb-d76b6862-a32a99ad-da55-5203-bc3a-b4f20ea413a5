"""Engine semantics tests — run: python -m pytest tests/ -q
(no pytest installed? use: python tests/test_engine.py)
"""
import json

from app.engine import (
    HashSaltMissing,
    build_audit,
    compile_rule,
    run_masking,
    format_path,
)

SALT = "global-salt"


def _g(result, canonical):
    return next(g for g in result.groups if g["canonical_path"] == canonical)


def test_priority_first_match_only():
    doc = {"a": {"b": {"secret": "x"}}}
    rules = [
        {"id": "r1", "name": "R1", "path": "$..secret", "action": "mask", "priority": 20, "params": {}},
        {"id": "r2", "name": "R2", "path": "$.a.b.secret", "action": "delete", "priority": 10, "params": {}},
    ]
    res = run_masking(doc, rules, SALT)
    assert res.document == {"a": {"b": {}}}, res.document
    g = _g(res, '$["a"]["b"]["secret"]')
    assert g["state"] == "delete"
    assert g["entries"][0]["rule_id"] == "r2"
    assert g["entries"][0]["status"] == "applied"
    assert g["entries"][1]["status"] == "skipped"
    assert "只执行首条" in g["entries"][1]["reason"]
    print("ok: priority first-match-only")


def test_parent_delete_blocks_children():
    doc = {"u": {"name": "张三", "id": "110101", "child": {"x": 1}}}
    rules = [
        {"id": "d", "name": "删u", "path": "$.u", "action": "delete", "priority": 1, "params": {}},
        {"id": "m", "name": "掩码name", "path": "$..name", "action": "mask", "priority": 2, "params": {}},
    ]
    res = run_masking(doc, rules, SALT)
    assert res.document == {}
    g = _g(res, '$["u"]["name"]')
    assert g["state"] == "blocked"
    assert g["entries"][0]["rule_id"] == "m"
    assert "祖先路径" in g["entries"][0]["reason"]
    # 子路径不能在结果中复活
    assert "name" not in json.dumps(res.document, ensure_ascii=False)
    print("ok: parent delete blocks children")


def test_parent_mask_blocks_descendant_rule():
    doc = {"o": {"a": 1, "b": 2}}
    rules = [
        {"id": "pm", "name": "父掩码", "path": "$.o", "action": "mask", "priority": 1,
         "params": {"mask_length": 3}},
        {"id": "cm", "name": "子删除", "path": "$.o.a", "action": "delete", "priority": 2, "params": {}},
    ]
    res = run_masking(doc, rules, SALT)
    assert isinstance(res.document["o"], str)
    g = _g(res, '$["o"]["a"]')
    assert g["state"] == "blocked"
    print("ok: parent replace blocks descendant rule")


def test_mask_options():
    doc = {"id": "110101199001011234"}
    rules = [{"id": "m", "name": "M", "path": "$.id", "action": "mask", "priority": 1,
              "params": {"keep_first": 4, "keep_last": 4, "mask_char": "*", "mask_length": 10}}]
    res = run_masking(doc, rules, SALT)
    assert res.document["id"] == "1101**********1234", res.document["id"]
    print("ok: mask keep first/last + fixed length")


def test_hash_with_salt_and_truncation_deterministic():
    doc = {"e1": "a@x.com", "e2": "a@x.com", "e3": "b@x.com"}
    rules = [{"id": "h", "name": "H", "path": "$.*", "action": "hash", "priority": 1,
              "params": {"salt": "rule-salt", "length": 16}}]
    res = run_masking(doc, rules, SALT)
    h1, h2, h3 = res.document["e1"], res.document["e2"], res.document["e3"]
    assert len(h1) == 16
    assert h1 == h2 and h1 != h3
    # different global salt ⇒ different output
    res2 = run_masking(doc, rules, "other-salt")
    assert res2.document["e1"] != h1
    # rerun stable
    res3 = run_masking(doc, rules, SALT)
    assert res3.document == res.document
    print("ok: salted hash deterministic / different value different hash")


def test_hash_without_global_salt_raises():
    doc = {"e": "a@x.com"}
    rules = [{"id": "h", "name": "H", "path": "$.e", "action": "hash", "priority": 1, "params": {}}]
    try:
        run_masking(doc, rules, None)
    except HashSaltMissing:
        print("ok: hash without global salt raises")
    else:
        raise AssertionError("expected HashSaltMissing")


def test_stable_numbering_same_value_same_number():
    doc = {"rows": [
        {"city": "BJ", "v": 1},
        {"city": "SH", "v": 2},
        {"city": "BJ", "v": 3},
        {"city": "GZ", "v": 4},
        {"city": "SH", "v": 5},
    ]}
    rules = [{"id": "n", "name": "N", "path": "$.rows[*].city", "action": "number", "priority": 1,
              "params": {"prefix": "C", "padding": 3, "start": 1}}]
    res = run_masking(doc, rules, SALT)
    nums = [r["city"] for r in res.document["rows"]]
    assert nums == ["C001", "C002", "C001", "C003", "C002"], nums
    # rerun identical
    res2 = run_masking(doc, rules, SALT)
    assert res2.document == res.document
    print("ok: stable numbering same value same number, deterministic")


def test_numbering_counter_per_rule_and_blocked_not_consumed():
    doc = {"a": {"x": "k"}, "b": {"x": "k"}, "keep": {"x": "k"}}
    rules = [
        {"id": "d", "name": "D", "path": "$.a", "action": "delete", "priority": 1, "params": {}},
        {"id": "n", "name": "N", "path": "$..x", "action": "number", "priority": 2, "params": {}},
    ]
    res = run_masking(doc, rules, SALT)
    # $.a.x blocked ⇒ does not consume a number; $.b.x first applied ⇒ 1, $.keep.x same value ⇒ 1
    assert res.document == {"b": {"x": 1}, "keep": {"x": 1}}, res.document
    print("ok: blocked matches do not consume numbers")


def test_numbering_distinct_types_distinct_numbers():
    doc = {"a": 1, "b": "1", "c": True, "d": 1}
    rules = [{"id": "n", "name": "N", "path": "$.*", "action": "number", "priority": 1, "params": {}}]
    res = run_masking(doc, rules, SALT)
    vals = [res.document["a"], res.document["b"], res.document["c"], res.document["d"]]
    assert vals[0] == vals[3]
    assert len(set(vals)) == 3, vals
    print("ok: numbering distinguishes 1 / '1' / true")


def test_array_delete_index_safety():
    doc = {"items": [{"n": "a"}, {"n": "b"}, {"n": "c"}]}
    rules = [{"id": "d", "name": "D", "path": "$.items[0].n", "action": "delete", "priority": 1, "params": {}},
             {"id": "d2", "name": "D2", "path": "$.items[2]", "action": "delete", "priority": 1, "params": {}}]
    res = run_masking(doc, rules, SALT)
    assert res.document == {"items": [{}, {"n": "b"}]}, res.document
    print("ok: array element deletes safe")


def test_unmatched_marked_and_never_matched_rule():
    doc = {"a": 1}
    rules = [
        {"id": "hit", "name": "命中", "path": "$.a", "action": "mask", "priority": 1, "params": {}},
        {"id": "miss", "name": "无匹配", "path": "$.nope", "action": "mask", "priority": 2, "params": {}},
    ]
    res = run_masking(doc, rules, SALT)
    g = _g(res, '$["a"]')
    assert {u["rule_id"] for u in g["unmatched_rules"]} == {"miss"}
    stat_miss = next(s for s in res.rule_stats if s["rule_id"] == "miss")
    assert stat_miss["never_matched"] is True
    print("ok: unmatched rules per path + never-matched stat")


def test_disabled_rule_ignored():
    doc = {"a": "secret"}
    rules = [{"id": "m", "name": "M", "path": "$.a", "action": "mask", "priority": 1,
              "enabled": False, "params": {}}]
    res = run_masking(doc, rules, SALT)
    assert res.document == doc
    print("ok: disabled rule ignored")


def test_bad_jsonpath_collected_not_raised():
    doc = {"a": 1}
    rules = [
        {"id": "bad", "name": "坏规则", "path": "$[", "action": "mask", "priority": 1, "params": {}},
        {"id": "ok", "name": "好规则", "path": "$.a", "action": "mask", "priority": 2, "params": {}},
    ]
    res = run_masking(doc, rules, SALT)
    assert res.rule_errors and res.rule_errors[0]["rule_id"] == "bad"
    assert res.document["a"] != 1
    print("ok: bad rule reported, others still run")


def test_audit_has_no_values_or_salts():
    doc = {"e": "secret@example.com"}
    rules = [{"id": "h", "name": "H", "path": "$.e", "action": "hash", "priority": 1,
              "params": {"salt": "SECRET-RULE-SALT", "length": 8}}]
    res = run_masking(doc, rules, SALT)
    audit = build_audit(res)
    blob = json.dumps(audit, ensure_ascii=False)
    assert "secret@example.com" not in blob
    assert res.document["e"] not in blob
    assert "SECRET-RULE-SALT" not in blob
    assert "global-salt" not in blob
    # path and rule name are present
    e_group = next(p for p in audit["paths"] if p["canonical_path"] == '$["e"]')
    assert e_group["winner_rule_id"] == "h"
    print("ok: audit contains no values and no salts")


def test_root_delete():
    doc = {"a": 1}
    rules = [{"id": "d", "name": "D", "path": "$", "action": "delete", "priority": 1, "params": {}}]
    res = run_masking(doc, rules, SALT)
    assert res.document is None
    print("ok: root delete")


def test_canonical_path_unicode():
    assert format_path(("姓名", 0)) == '$["姓名"][0]'
    print("ok: canonical path unicode")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
    print(f"\nall {len(fns)} engine tests passed")
