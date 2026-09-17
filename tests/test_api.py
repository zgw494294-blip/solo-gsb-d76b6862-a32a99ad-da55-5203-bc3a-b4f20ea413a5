"""End-to-end API tests. Run: PYTHONPATH=. python tests/test_api.py"""
import json
import os
import tempfile

os.environ["MASKING_HASH_SALT"] = "test-salt"
_db_fd, db_path = tempfile.mkstemp(suffix=".db")
os.environ["SQLITE_PATH"] = db_path

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

with TestClient(app) as client:
    # health
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["hash_salt_configured"] is True

    doc = {"users": [
        {"name": "张三", "email": "a@x.com", "p": "x", "city": "BJ"},
        {"name": "李四", "email": "b@x.com", "p": "y", "city": "BJ"},
    ]}
    rules = [
        {"id": "d", "name": "删p", "path": "$..p", "action": "delete", "priority": 1},
        {"id": "h", "name": "邮箱哈希", "path": "$..email", "action": "hash", "priority": 2,
         "params": {"salt": "s", "length": 12}},
        {"id": "n", "name": "城市编号", "path": "$..city", "action": "number", "priority": 3,
         "params": {"prefix": "C", "padding": 2}},
    ]
    r = client.post("/api/mask/preview", json={"document": doc, "rules": rules})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["result"]["users"][0]["name"] == "张三"
    assert "p" not in data["result"]["users"][0]
    assert data["result"]["users"][0]["email"] != "a@x.com"
    # 同值同号
    assert data["result"]["users"][0]["city"] == data["result"]["users"][1]["city"] == "C01"
    assert data["summary"]["deleted"] == 2
    # 每组包含原值和未命中规则列表
    grp = next(g for g in data["groups"] if g["canonical_path"] == '$["users"][0]["name"]')
    assert grp["state"] == "unmatched" and grp["original"] == "张三"

    # 导出脱敏 JSON
    r = client.post("/api/mask/export", json={"document": doc, "rules": rules})
    assert r.status_code == 200
    masked = r.json()
    assert masked == data["result"]
    assert "a@x.com" not in json.dumps(masked, ensure_ascii=False)

    # 审计清单：无原值、无结果值、无盐
    r = client.post("/api/mask/audit", json={"document": doc, "rules": rules})
    assert r.status_code == 200
    audit_text = r.text
    assert "a@x.com" not in audit_text
    assert "b@x.com" not in audit_text
    assert "test-salt" not in audit_text
    # 规则盐 params 不出现在审计清单
    assert json.dumps({"salt": "s"}) not in audit_text
    audit = r.json()
    assert audit["export_kind"] == "audit"

    # hash 规则在无全局盐时 400
    from app import main as main_mod
    main_mod.settings = main_mod.get_settings()
    # 直接调用引擎层已覆盖；此处验证错误体结构（通过临时替换 settings）
    import dataclasses
    no_salt = dataclasses.replace(main_mod.settings, masking_hash_salt=None)
    main_mod.settings = no_salt
    r = client.post("/api/mask/preview", json={"document": doc, "rules": rules})
    assert r.status_code == 400 and "MASKING_HASH_SALT" in r.json()["detail"]

    # 模板 CRUD
    r = client.post("/api/templates", json={"name": "T1", "description": "d", "rules": rules})
    assert r.status_code == 201, r.text
    tpl = r.json()
    assert tpl["rules"][1]["path"] == "$..email"
    r = client.get("/api/templates")
    assert any(t["name"] == "T1" for t in r.json())
    r = client.put(f"/api/templates/{tpl['id']}", json={"name": "T1b", "description": "", "rules": []})
    assert r.status_code == 200 and r.json()["name"] == "T1b"
    r = client.delete(f"/api/templates/{tpl['id']}")
    assert r.status_code == 204
    r = client.delete("/api/templates/nope")
    assert r.status_code == 404

    # 校验：非对象顶层
    r = client.post("/api/mask/preview", json={"document": 42, "rules": []})
    assert r.status_code == 422

    # 首页
    r = client.get("/")
    assert r.status_code == 200 and "JSON 数据脱敏工作台" in r.text
    r = client.get("/static/app.js")
    assert r.status_code == 200

    # 超限请求
    big = {"document": {"k": "x" * 2000}, "rules": []}
    # content-length 实际很小，这里走正常路径；单独构造超长 header 场景跳过
    r = client.post("/api/mask/preview", json=big)
    assert r.status_code == 200

print("all API tests passed")
