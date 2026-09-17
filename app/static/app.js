/* JSON 数据脱敏工作台 —— 前端逻辑（原生 JS，无框架） */
"use strict";

const $ = (sel) => document.querySelector(sel);

const state = {
  rules: [],
  currentTemplateId: null,
  lastResult: null, // { masked, report, audit }
};

/* ---------------- 工具 ---------------- */

function toast(msg, ms = 2200) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add("hidden"), ms);
}

async function api(method, url, body) {
  const resp = await fetch(url, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = (await resp.json()).detail || detail; } catch (_) { /* ignore */ }
    throw new Error(detail);
  }
  return resp.json();
}

function download(filename, text, mime = "application/json") {
  const blob = new Blob([text], { type: mime + ";charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function shortVal(v, max = 90) {
  let s = JSON.stringify(v);
  if (s === undefined) s = String(v);
  return s.length > max ? s.slice(0, max) + "…" : s;
}

/* ---------------- 规则编辑器 ---------------- */

function newRule() {
  return {
    id: "rule-" + Math.random().toString(36).slice(2, 8),
    name: "",
    path: "$.",
    action: "mask",
    priority: 100,
    enabled: true,
    mask_char: "*",
    keep_length: false,
    fixed_length: 8,
    salt: "",
    hash_length: 16,
    prefix: "ID",
  };
}

const ACTION_LABELS = { delete: "删除", mask: "掩码", hash: "带盐哈希", number: "稳定编号" };

function paramsHtml(rule) {
  switch (rule.action) {
    case "delete":
      return '<span class="muted">（无参数）</span>';
    case "mask":
      return `
        <label>字符 <input type="text" data-k="mask_char" maxlength="1" value="${esc(rule.mask_char)}" style="width:34px"></label>
        <label><input type="checkbox" data-k="keep_length" ${rule.keep_length ? "checked" : ""}> 保持长度</label>
        <label>固定长度 <input type="number" data-k="fixed_length" min="1" max="128" value="${rule.fixed_length}"></label>`;
    case "hash":
      return `
        <label>盐 <input type="text" data-k="salt" placeholder="留空用服务器盐" value="${esc(rule.salt)}"></label>
        <label>长度 <input type="number" data-k="hash_length" min="4" max="64" value="${rule.hash_length}"></label>`;
    case "number":
      return `<label>前缀 <input type="text" data-k="prefix" value="${esc(rule.prefix)}"></label>
              <span class="muted">同值同号，按首次出现编号</span>`;
    default:
      return "";
  }
}

function esc(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderRules() {
  const tbody = $("#rulesBody");
  tbody.innerHTML = "";
  state.rules.forEach((rule, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><input type="checkbox" data-k="enabled" ${rule.enabled ? "checked" : ""}></td>
      <td><input type="number" data-k="priority" value="${rule.priority}" style="width:60px"></td>
      <td><input type="text" data-k="name" placeholder="规则名" value="${esc(rule.name)}"></td>
      <td><input type="text" data-k="path" value="${esc(rule.path)}" style="font-family:var(--mono)"></td>
      <td><select data-k="action">
        ${Object.entries(ACTION_LABELS).map(([v, l]) =>
          `<option value="${v}" ${rule.action === v ? "selected" : ""}>${l}</option>`).join("")}
      </select></td>
      <td class="rule-params">${paramsHtml(rule)}</td>
      <td class="row-btns">
        <button data-op="up" title="上移">↑</button>
        <button data-op="down" title="下移">↓</button>
        <button data-op="del" title="删除" class="danger">✕</button>
      </td>`;

    tr.querySelectorAll("[data-k]").forEach((el) => {
      el.addEventListener("change", () => {
        const k = el.dataset.k;
        let v;
        if (el.type === "checkbox") v = el.checked;
        else if (el.type === "number") v = Number(el.value);
        else v = el.value;
        rule[k] = v;
        if (k === "action") renderRules(); // 参数区随动作变化
      });
    });
    tr.querySelectorAll("[data-op]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const op = btn.dataset.op;
        if (op === "del") state.rules.splice(idx, 1);
        if (op === "up" && idx > 0) [state.rules[idx - 1], state.rules[idx]] = [state.rules[idx], state.rules[idx - 1]];
        if (op === "down" && idx < state.rules.length - 1) [state.rules[idx + 1], state.rules[idx]] = [state.rules[idx], state.rules[idx + 1]];
        renderRules();
      });
    });
    tbody.appendChild(tr);
  });
}

/* ---------------- 预览 ---------------- */

function parseInput() {
  const raw = $("#jsonInput").value.trim();
  if (!raw) throw new Error("请先粘贴 JSON 数据");
  return JSON.parse(raw);
}

function rulesPayload() {
  return state.rules.map((r) => ({
    ...r,
    name: r.name || r.path,
    salt: r.salt === "" ? null : r.salt,
  }));
}

async function runPreview() {
  $("#jsonError").textContent = "";
  let data;
  try {
    data = parseInput();
  } catch (e) {
    $("#jsonError").textContent = "JSON 解析失败：" + e.message;
    return;
  }
  let result;
  try {
    result = await api("POST", "/api/preview", { data, rules: rulesPayload() });
  } catch (e) {
    $("#jsonError").textContent = "预览失败：" + e.message;
    return;
  }
  state.lastResult = result;
  $("#previewOriginal").textContent = JSON.stringify(data, null, 2);
  $("#previewMasked").textContent = JSON.stringify(result.masked, null, 2);
  renderReport();
  ["#btnExportJson", "#btnExportAuditJson", "#btnExportAuditCsv"]
    .forEach((s) => { $(s).disabled = false; });
  toast("预览完成");
}

const STATUS_LABELS = { matched: "已命中", unmatched: "未命中", skipped: "已跳过" };

function renderReport() {
  const filter = $("#reportFilter").value;
  const report = state.lastResult ? state.lastResult.report : [];
  const tbody = $("#reportBody");
  tbody.innerHTML = "";
  const counts = { matched: 0, unmatched: 0, skipped: 0 };
  report.forEach((e) => { counts[e.status] += 1; });
  $("#reportStats").textContent =
    `共 ${report.length} 条路径 · 命中 ${counts.matched} · 未命中 ${counts.unmatched} · 跳过 ${counts.skipped}`;
  report
    .filter((e) => !filter || e.status === filter)
    .forEach((e) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="path">${esc(e.path)}</td>
        <td><span class="status ${e.status}">${STATUS_LABELS[e.status]}</span></td>
        <td>${e.rule_name ? esc(e.rule_name) : "—"}</td>
        <td>${e.action ? ACTION_LABELS[e.action] : "—"}</td>
        <td class="val" title="${esc(shortVal(e.original, 400))}">${esc(shortVal(e.original))}</td>
        <td class="val" title="${esc(shortVal(e.result, 400))}">${e.result === null || e.result === undefined ? "—" : esc(shortVal(e.result))}</td>`;
      tbody.appendChild(tr);
    });
}

/* ---------------- 导出（均不含原值） ---------------- */

function exportMasked() {
  if (!state.lastResult) return;
  download("masked.json", JSON.stringify(state.lastResult.masked, null, 2));
}

function exportAuditJson() {
  if (!state.lastResult) return;
  download("audit.json", JSON.stringify(state.lastResult.audit, null, 2));
}

function csvCell(v) {
  if (v === null || v === undefined) return "";
  let s = typeof v === "string" ? v : JSON.stringify(v);
  return '"' + s.replace(/"/g, '""') + '"';
}

function exportAuditCsv() {
  if (!state.lastResult) return;
  const header = "path,status,rule_id,rule_name,action,result";
  const lines = state.lastResult.audit.map((e) =>
    [e.path, e.status, e.rule_id, e.rule_name, e.action, e.result].map(csvCell).join(","));
  download("audit.csv", "\uFEFF" + header + "\n" + lines.join("\n"), "text/csv");
}

/* ---------------- 模板 ---------------- */

async function refreshTemplates(selectId) {
  const list = await api("GET", "/api/templates");
  const sel = $("#templateSelect");
  sel.innerHTML = '<option value="">（未选择）</option>' +
    list.map((t) => `<option value="${t.id}">${esc(t.name)}（${t.rule_count} 条规则）</option>`).join("");
  if (selectId) sel.value = selectId;
}

async function loadTemplate() {
  const id = $("#templateSelect").value;
  if (!id) return toast("请先选择模板");
  const tpl = await api("GET", "/api/templates/" + id);
  state.rules = tpl.rules.map((r) => ({ ...newRule(), ...r }));
  state.currentTemplateId = id;
  renderRules();
  toast(`已加载模板「${tpl.name}」`);
}

async function saveTemplate() {
  if (state.currentTemplateId) {
    const tplName = $("#templateSelect").selectedOptions[0].textContent;
    const pureName = tplName.replace(/（\d+ 条规则）$/, "");
    await api("PUT", "/api/templates/" + state.currentTemplateId, { name: pureName, rules: rulesPayload() });
    await refreshTemplates(state.currentTemplateId);
    toast("模板已更新");
  } else {
    saveTemplateAs();
  }
}

async function saveTemplateAs() {
  const name = prompt("模板名称：", "我的脱敏模板");
  if (!name) return;
  const tpl = await api("POST", "/api/templates", { name, rules: rulesPayload() });
  state.currentTemplateId = tpl.id;
  await refreshTemplates(tpl.id);
  toast(`模板「${name}」已保存`);
}

async function deleteTemplate() {
  const id = $("#templateSelect").value;
  if (!id) return toast("请先选择模板");
  if (!confirm("确定删除该模板？")) return;
  await api("DELETE", "/api/templates/" + id);
  state.currentTemplateId = null;
  await refreshTemplates();
  toast("模板已删除");
}

/* ---------------- 示例 ---------------- */

const SAMPLE_DATA = {
  company: "示例科技",
  users: [
    { id: 1, name: "张三", phone: "13800001111", email: "zhangsan@example.com",
      id_card: "11010119900307777X", role: "admin",
      address: { city: "北京", detail: "海淀区中关村大街 1 号" } },
    { id: 2, name: "李四", phone: "13900002222", email: "lisi@example.com",
      id_card: "310104198811223344", role: "user",
      address: { city: "上海", detail: "浦东新区世纪大道 100 号" } },
    { id: 3, name: "张三", phone: "13800001111", email: "zs2@example.com",
      id_card: "11010119900307777X", role: "user",
      address: { city: "北京", detail: "海淀区中关村大街 1 号" } }
  ],
  tokens: ["tok-abc-123", "tok-def-456"],
  meta: { exported_by: "ops@example.com", note: null }
};

const SAMPLE_RULES = [
  { name: "删除导出备注", path: "$.meta.note", action: "delete", priority: 10 },
  { name: "身份证掩码", path: "$.users[*].id_card", action: "mask", priority: 20,
    mask_char: "*", keep_length: true },
  { name: "手机号哈希", path: "$.users[*].phone", action: "hash", priority: 30, hash_length: 16 },
  { name: "姓名稳定编号", path: "$.users[*].name", action: "number", priority: 40, prefix: "USER" },
  { name: "邮箱掩码", path: "$..email", action: "mask", priority: 50, fixed_length: 8 },
  { name: "令牌删除", path: "$.tokens", action: "delete", priority: 5 },
];

function loadSample() {
  $("#jsonInput").value = JSON.stringify(SAMPLE_DATA, null, 2);
  state.rules = SAMPLE_RULES.map((r) => ({ ...newRule(), ...r }));
  renderRules();
  $("#jsonError").textContent = "";
  toast("示例已载入，点击「运行预览」");
}

/* ---------------- 启动 ---------------- */

function init() {
  $("#btnAddRule").addEventListener("click", () => { state.rules.push(newRule()); renderRules(); });
  $("#btnRun").addEventListener("click", () => { runPreview().catch((e) => toast(e.message)); });
  $("#btnFormat").addEventListener("click", () => {
    try { $("#jsonInput").value = JSON.stringify(parseInput(), null, 2); $("#jsonError").textContent = ""; }
    catch (e) { $("#jsonError").textContent = "JSON 解析失败：" + e.message; }
  });
  $("#btnClear").addEventListener("click", () => { $("#jsonInput").value = ""; });
  $("#btnSample").addEventListener("click", loadSample);
  $("#reportFilter").addEventListener("change", renderReport);
  $("#btnExportJson").addEventListener("click", exportMasked);
  $("#btnExportAuditJson").addEventListener("click", exportAuditJson);
  $("#btnExportAuditCsv").addEventListener("click", exportAuditCsv);
  $("#btnLoadTemplate").addEventListener("click", () => loadTemplate().catch((e) => toast(e.message)));
  $("#btnSaveTemplate").addEventListener("click", () => saveTemplate().catch((e) => toast(e.message)));
  $("#btnSaveTemplateAs").addEventListener("click", () => saveTemplateAs().catch((e) => toast(e.message)));
  $("#btnDeleteTemplate").addEventListener("click", () => deleteTemplate().catch((e) => toast(e.message)));
  refreshTemplates().catch(() => toast("模板列表加载失败"));
  renderRules();
}

document.addEventListener("DOMContentLoaded", init);
