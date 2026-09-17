/* 本地 JSON 脱敏工作台 — 原生 JS（无框架、无 CDN，离线可用） */
"use strict";

const $ = (sel) => document.querySelector(sel);

const ACTION_LABELS = {
  delete: "删除",
  mask: "掩码",
  hash: "带盐哈希",
  number: "稳定编号",
};

const SAMPLE_JSON = {
  request_id: "REQ-20260917-0007",
  users: [
    {
      name: "张三",
      id_card: "110101199003078888",
      phone: "13812345678",
      email: "zhangsan@example.com",
      salary: 26000,
      department: "研发部",
      password_hash: "5f4dcc3b5aa765d61d8327deb882cf99",
      address: { country: "中国", province: "北京", detail: "海淀区中关村大街1号" },
    },
    {
      name: "李四",
      id_card: "310104199201126666",
      phone: "13987654321",
      email: "lisi@example.com",
      salary: 32000,
      department: "研发部",
      password_hash: "098f6bcd4621d373cade4e832627b4f6",
      address: { country: "中国", province: "上海", detail: "浦东新区世纪大道100号" },
    },
    {
      name: "王五",
      id_card: "440106198805231111",
      phone: "13700001111",
      email: "wangwu@example.com",
      salary: 18000,
      department: "市场部",
      password_hash: "e10adc3949ba59abbe56e057f20f883e",
      address: { country: "中国", province: "广东", detail: "广州市天河路200号" },
    },
  ],
};

const SAMPLE_RULES = [
  {
    id: uid(),
    name: "删除密码哈希",
    path: "$..password_hash",
    action: "delete",
    priority: 10,
    enabled: true,
    params: {},
  },
  {
    id: uid(),
    name: "身份证掩码",
    path: "$..id_card",
    action: "mask",
    priority: 20,
    enabled: true,
    params: { keep_first: 4, keep_last: 4, mask_char: "*", mask_length: 10 },
  },
  {
    id: uid(),
    name: "手机号掩码",
    path: "$..phone",
    action: "mask",
    priority: 30,
    enabled: true,
    params: { keep_first: 3, keep_last: 2, mask_char: "*", mask_length: 4 },
  },
  {
    id: uid(),
    name: "邮箱哈希",
    path: "$..email",
    action: "hash",
    priority: 40,
    enabled: true,
    params: { salt: "email-rule", length: 16 },
  },
  {
    id: uid(),
    name: "部门稳定编号（同部门同号）",
    path: "$..department",
    action: "number",
    priority: 50,
    enabled: true,
    params: { prefix: "D", suffix: "", padding: 3, start: 1 },
  },
  {
    id: uid(),
    name: "地址整体删除（子路径规则将被跳过）",
    path: "$..address",
    action: "delete",
    priority: 5,
    enabled: true,
    params: {},
  },
  {
    id: uid(),
    name: "省份掩码（演示被父规则阻断）",
    path: "$..province",
    action: "mask",
    priority: 1,
    enabled: true,
    params: { keep_first: 0, keep_last: 0, mask_char: "*", mask_length: null },
  },
];

function uid() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return "id-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8);
}

let rules = [];
let lastPreview = null;
let editingTemplateId = null;
let showOnlyHit = false;

// --------------------------------------------------------------------------- //
// Rule editor
// --------------------------------------------------------------------------- //

function defaultParams(action) {
  if (action === "mask")
    return { keep_first: 0, keep_last: 0, mask_char: "*", mask_length: null };
  if (action === "hash") return { salt: "", length: 64 };
  if (action === "number") return { prefix: "U", suffix: "", padding: 4, start: 1 };
  return {};
}

function addRule(preset) {
  const action = preset?.action || "mask";
  rules.push({
    id: uid(),
    name: preset?.name || `规则 ${rules.length + 1}`,
    path: preset?.path || "$..",
    action,
    priority: preset?.priority ?? (rules.length + 1) * 10,
    enabled: preset?.enabled ?? true,
    params: preset?.params ? { ...preset.params } : defaultParams(action),
  });
  renderRules();
}

function removeRule(id) {
  rules = rules.filter((r) => r.id !== id);
  renderRules();
}

function moveRule(index, dir) {
  const target = index + dir;
  if (target < 0 || target >= rules.length) return;
  [rules[index], rules[target]] = [rules[target], rules[index]];
  renderRules();
}

function renderRules() {
  const list = $("#rulesList");
  list.innerHTML = "";
  rules.forEach((rule, index) => {
    const item = document.createElement("div");
    item.className = "rule-item";
    item.dataset.id = rule.id;

    const row1 = document.createElement("div");
    row1.className = "rule-row";
    row1.innerHTML = `
      <div class="rule-move">
        <button type="button" title="上移" data-act="up">▲</button>
        <button type="button" title="下移" data-act="down">▼</button>
      </div>
      <label class="rule-enable"><input type="checkbox" data-f="enabled" ${rule.enabled ? "checked" : ""}/>启用</label>
      <input class="input r-name" type="text" data-f="name" maxlength="100" />
      <input class="input r-prio" type="number" data-f="priority" title="优先级（小者先）" />
      <select class="r-action" data-f="action">
        ${Object.keys(ACTION_LABELS).map(
          (a) => `<option value="${a}" ${a === rule.action ? "selected" : ""}>${ACTION_LABELS[a]}</option>`
        ).join("")}
      </select>
      <button class="btn btn-danger btn-mini" data-act="del" type="button">删除</button>
    `;
    row1.querySelector('[data-f="name"]').value = rule.name;
    row1.querySelector('[data-f="priority"]').value = rule.priority;

    const row2 = document.createElement("div");
    row2.className = "rule-row";
    row2.innerHTML = `
      <span class="hint" style="margin:0">JSONPath</span>
      <input class="input r-path" type="text" data-f="path" maxlength="1000" spellcheck="false" />`;
    row2.querySelector('[data-f="path"]').value = rule.path;

    const paramsBox = document.createElement("div");
    paramsBox.className = "r-params";
    renderParamsBox(paramsBox, rule);

    item.append(row1, row2, paramsBox);
    list.appendChild(item);

    // Bindings — input 事件直接改状态，不重绘，避免输入焦点丢失。
    item.querySelectorAll("[data-f]").forEach((el) => {
      const f = el.dataset.f;
      el.addEventListener("input", () => {
        if (f === "priority") rule.priority = parseInt(el.value || "0", 10);
        else if (f === "enabled") rule.enabled = el.checked;
        else rule[f] = el.value;
      });
      el.addEventListener("change", () => {
        if (f === "action") {
          rule.action = el.value;
          rule.params = defaultParams(el.value);
          renderParamsBox(paramsBox, rule);
        }
      });
    });
    item.querySelectorAll("[data-act]").forEach((btn) =>
      btn.addEventListener("click", () => {
        const act = btn.dataset.act;
        if (act === "del") removeRule(rule.id);
        if (act === "up") moveRule(index, -1);
        if (act === "down") moveRule(index, 1);
      })
    );
  });
}

function paramInput(rule, key, label, { wide = false, type = "number", placeholder = "" } = {}) {
  const wrap = document.createElement("label");
  const val = rule.params[key];
  wrap.innerHTML = `${label}
    <input class="${wide ? "wide" : ""}" type="${type}" placeholder="${placeholder}" />`;
  const input = wrap.querySelector("input");
  input.value = val === null || val === undefined ? "" : val;
  input.addEventListener("input", () => {
    if (type === "number") {
      rule.params[key] = input.value === "" ? null : parseInt(input.value, 10);
    } else {
      rule.params[key] = input.value;
    }
  });
  return wrap;
}

function renderParamsBox(box, rule) {
  box.innerHTML = "";
  if (rule.action === "mask") {
    box.append(
      paramInput(rule, "keep_first", "保留前 N 位"),
      paramInput(rule, "keep_last", "保留后 N 位"),
      paramInput(rule, "mask_char", "掩码字符", { type: "text" }),
      paramInput(rule, "mask_length", "掩码长度(空=同长)"),
      hintNode("非字符串值会先转成规范 JSON 文本再掩码")
    );
  } else if (rule.action === "hash") {
    box.append(
      paramInput(rule, "salt", "规则盐", { wide: true, type: "text" }),
      paramInput(rule, "length", "输出长度 1-64"),
      hintNode("全局盐由环境变量 MASKING_HASH_SALT 提供，不进入导出清单")
    );
  } else if (rule.action === "number") {
    box.append(
      paramInput(rule, "prefix", "前缀", { type: "text" }),
      paramInput(rule, "suffix", "后缀", { type: "text" }),
      paramInput(rule, "padding", "补零宽度(0=不补)"),
      paramInput(rule, "start", "起始值"),
      hintNode("同一规则内按首次出现编号：同值同号、异值异号")
    );
  } else {
    box.append(hintNode("删除动作无可选参数：父节点删除后子路径不再处理"));
  }
}

function hintNode(text) {
  const span = document.createElement("span");
  span.className = "hint";
  span.textContent = text;
  return span;
}

// --------------------------------------------------------------------------- //
// JSON helpers / canonical paths (must match engine.format_path)
// --------------------------------------------------------------------------- //

function canonPath(path) {
  return (
    "$" +
    path
      .map((part) =>
        typeof part === "number"
          ? `[${part}]`
          : `[${JSON.stringify(part)}]`
      )
      .join("")
  );
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function scalarHtml(value, maxLen = 80) {
  let cls = "v-null";
  let text;
  if (value === null) {
    text = "null";
  } else if (typeof value === "string") {
    cls = "v-string";
    text = '"' + truncate(escapeHtml(value), maxLen) + '"';
  } else if (typeof value === "number") {
    cls = "v-number";
    text = String(value);
  } else if (typeof value === "boolean") {
    cls = "v-bool";
    text = String(value);
  } else {
    cls = "v-null";
    text = escapeHtml(truncate(JSON.stringify(value), maxLen));
  }
  return { cls, text };
}

// --------------------------------------------------------------------------- //
// Tree rendering
// --------------------------------------------------------------------------- //

function badgeFor(group) {
  if (!group) return "";
  const ruleName = group.winner_rule_id
    ? (group.entries.find((e) => e.status === "applied" || e.status === "blocked")?.rule_name ||
      group.entries[0]?.rule_name)
    : null;
  const tail = ruleName ? ` · ${escapeHtml(ruleName)}` : "";
  switch (group.state) {
    case "delete":
      return `<span class="badge badge-delete">删除${tail}</span>`;
    case "mask":
      return `<span class="badge badge-mask">掩码${tail}</span>`;
    case "hash":
      return `<span class="badge badge-hash">哈希${tail}</span>`;
    case "number":
      return `<span class="badge badge-number">编号${tail}</span>`;
    case "blocked":
      return `<span class="badge badge-blocked">跳过·祖先规则</span>`;
    default:
      return "";
  }
}

function renderTree(container, data, groupsByPath, mode) {
  container.innerHTML = "";
  if (mode === "result") {
    // After array deletions result indices shift; recover the original
    // index by skipping deleted survivors in DFS order.
    const deleted = new Set(
      [...groupsByPath.values()]
        .filter((g) => g.state === "delete")
        .map((g) => g.canonical_path)
    );
    container.appendChild(
      buildResultNode(data, [], true, groupsByPath, deleted)
    );
  } else {
    container.appendChild(buildNode(data, [], true, groupsByPath, "orig"));
  }
}

function buildResultNode(value, origPath, isRoot, groupsByPath, deletedSet) {
  // origPath uses *original* indices; deleted original subtrees are skipped.
  const wrap = document.createElement("div");
  const canonical = canonPath(origPath);
  const group = groupsByPath.get(canonical);
  const nodeLine = document.createElement("div");
  nodeLine.className = "node";

  const keyHtml = isRoot
    ? ""
    : `<span class="k">${
        typeof origPath[origPath.length - 1] === "number"
          ? origPath[origPath.length - 1]
          : escapeHtml(JSON.stringify(origPath[origPath.length - 1]))
      }</span><span class="punct">: </span>`;

  const isObj = value && typeof value === "object";
  if (group && ["mask", "hash", "number"].includes(group.state)) {
    nodeLine.classList.add("row-change");
  }

  if (!isObj) {
    const { cls, text } = scalarHtml(value);
    nodeLine.innerHTML =
      `<span class="toggle"></span>${keyHtml}<span class="${cls}">${text}</span>` +
      badgeFor(group);
    wrap.appendChild(nodeLine);
    return wrap;
  }

  const isArr = Array.isArray(value);
  let entries;
  if (isArr) {
    // Walk original indices, skipping deleted ones, and zip with survivors.
    const parentCanon = isRoot ? "$" : canonical;
    let next = 0;
    let origIdx = 0;
    const zipped = [];
    while (next < value.length) {
      let childCanon = parentCanon + "[" + origIdx + "]";
      if (deletedSet.has(childCanon)) {
        origIdx++;
        continue;
      }
      zipped.push([origIdx, value[next]]);
      origIdx++;
      next++;
    }
    entries = zipped;
  } else {
    entries = Object.entries(value);
  }
  const summary = isArr ? `Array[${entries.length}]` : `{${entries.length} 个键}`;

  const toggle = document.createElement("span");
  toggle.className = "toggle";
  toggle.textContent = "▾";
  nodeLine.append(toggle);
  nodeLine.insertAdjacentHTML(
    "beforeend",
    `${keyHtml}<span class="punct">${summary}</span>${badgeFor(group)}`
  );

  const children = document.createElement("div");
  children.className = "children";
  for (const [origKey, child] of entries) {
    children.appendChild(
      buildResultNode(child, origPath.concat([origKey]), false, groupsByPath, deletedSet)
    );
  }
  toggle.addEventListener("click", () => {
    children.classList.toggle("collapsed");
    toggle.textContent = children.classList.contains("collapsed") ? "▸" : "▾";
  });

  wrap.append(nodeLine, children);
  return wrap;
}

function buildNode(value, path, isRoot, groupsByPath, mode) {
  const wrap = document.createElement("div");
  const canonical = canonPath(path);
  const group = groupsByPath.get(canonical);

  const nodeLine = document.createElement("div");
  nodeLine.className = "node";

  const keyHtml = isRoot
    ? ""
    : `<span class="k">${
        typeof path[path.length - 1] === "number"
          ? path[path.length - 1]
          : escapeHtml(JSON.stringify(path[path.length - 1]))
      }</span><span class="punct">: </span>`;

  const isObj = value && typeof value === "object";
  let badge = "";
  let rowClass = "";

  if (mode === "orig" && group) {
    badge = badgeFor(group);
    if (group.state === "delete") rowClass = "row-delete";
    else if (group.state === "blocked") rowClass = "row-blocked";
    else if (group.state !== "unmatched") rowClass = "row-change";
  }
  if (mode === "result" && group && ["mask", "hash", "number"].includes(group.state)) {
    badge = badgeFor(group);
    rowClass = "row-change";
  }
  if (nodeLine) nodeLine.classList.add(...rowClass.split(" ").filter(Boolean));

  if (!isObj) {
    const { cls, text } = scalarHtml(value);
    let unmatchedBadge = "";
    if (mode === "orig" && group && group.state === "unmatched") {
      unmatchedBadge = '<span class="badge badge-unmatched">未命中</span>';
    }
    nodeLine.innerHTML =
      `<span class="toggle"></span>${keyHtml}<span class="${cls}">${text}</span>` +
      badge +
      unmatchedBadge;
    wrap.appendChild(nodeLine);
    return wrap;
  }

  const entries = Array.isArray(value)
    ? value.map((v, i) => [i, v])
    : Object.entries(value);
  const summary = Array.isArray(value)
    ? `Array[${entries.length}]`
    : `{${entries.length} 个键}`;

  const toggle = document.createElement("span");
  toggle.className = "toggle";
  toggle.textContent = "▾";
  nodeLine.append(toggle);
  nodeLine.insertAdjacentHTML("beforeend", `${keyHtml}<span class="punct">${summary}</span>${badge}`);

  const children = document.createElement("div");
  children.className = "children";
  for (const [k, child] of entries) {
    children.appendChild(
      buildNode(child, path.concat([k]), false, groupsByPath, mode)
    );
  }

  toggle.addEventListener("click", () => {
    children.classList.toggle("collapsed");
    toggle.textContent = children.classList.contains("collapsed") ? "▸" : "▾";
  });

  wrap.append(nodeLine, children);
  return wrap;
}

// --------------------------------------------------------------------------- //
// Report table
// --------------------------------------------------------------------------- //

function renderReport(groups) {
  const body = $("#reportBody");
  body.innerHTML = "";
  for (const g of groups) {
    if (showOnlyHit && g.state === "unmatched") continue;
    const tr = document.createElement("tr");

    const stateLabel = {
      delete: ["删除", "state-delete"],
      mask: ["掩码", "state-mask"],
      hash: ["带盐哈希", "state-hash"],
      number: ["稳定编号", "state-number"],
      blocked: ["子路径跳过", "state-blocked"],
      unmatched: ["未命中", "state-unmatched"],
    }[g.state];

    const winnerEntry = g.entries.find((e) => e.status === "applied");
    const winner = winnerEntry
      ? `${escapeHtml(winnerEntry.rule_name)} <span class="hint">P${winnerEntry.priority} · ${ACTION_LABELS[winnerEntry.action]}</span>`
      : "—";

    const origText =
      g.state === "blocked"
        ? "—"
        : g.original === undefined
        ? ""
        : escapeHtml(truncate(stringifyForTable(g.original), 120));
    let resultText;
    if (g.state === "delete") resultText = "∅ 已删除";
    else if (g.state === "blocked") resultText = "— 祖先节点已处理，子树不存在";
    else if (["mask", "hash", "number"].includes(g.state))
      resultText = escapeHtml(truncate(stringifyForTable(g.result), 120));
    else resultText = origText;

    const detailLines = [];
    for (const e of g.entries) {
      if (e.status === "applied") continue;
      detailLines.push(
        `<div class="rule-line ${e.status}">${
          e.status === "skipped" ? "未执行" : "阻断"
        }：${escapeHtml(e.rule_name)} <span class="why">— ${escapeHtml(e.reason || "")}</span></div>`
      );
    }
    if (g.unmatched_rules.length) {
      detailLines.push(
        `<div class="rule-line"><span class="hint">未命中：${escapeHtml(
          g.unmatched_rules.map((r) => r.rule_name).join("、")
        )}</span></div>`
      );
    }

    tr.innerHTML = `
      <td><span class="path">${escapeHtml(g.path)}</span></td>
      <td><span class="state-tag ${stateLabel[1]}">${stateLabel[0]}</span></td>
      <td>${winner}</td>
      <td><span class="val">${origText}</span></td>
      <td><span class="val">${resultText}</span></td>
      <td><div class="rule-detail">${detailLines.join("") || '<span class="hint">—</span>'}</div></td>`;
    body.appendChild(tr);
  }
}

function stringifyForTable(value) {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

// --------------------------------------------------------------------------- //
// Preview flow
// --------------------------------------------------------------------------- //

function readDocument() {
  const text = $("#jsonInput").value;
  return JSON.parse(text);
}

async function runPreview() {
  $("#jsonError").textContent = "";
  let document;
  try {
    document = readDocument();
  } catch (err) {
    $("#jsonError").textContent = "JSON 解析失败：" + err.message;
    return;
  }
  try {
    const resp = await fetch("/api/mask/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ document, rules }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      $("#jsonError").textContent = data.detail || "预览失败";
      return;
    }
    lastPreview = data;
    renderPreview(data, document);
    $("#btnExportJson").disabled = false;
    $("#btnExportAudit").disabled = false;
  } catch (err) {
    $("#jsonError").textContent = "请求失败：" + err.message;
  }
}

function renderPreview(data, document) {
  const groupsByPath = new Map(data.groups.map((g) => [g.canonical_path, g]));
  renderTree($("#origTree"), document, groupsByPath, "orig");
  renderTree($("#resultTree"), data.result, groupsByPath, "result");
  renderReport(data.groups);

  const s = data.summary;
  const bar = $("#summaryBar");
  bar.classList.remove("hidden");
  bar.innerHTML = `
    <span class="chip">路径 ${s.paths_total}</span>
    <span class="chip chip-delete">删除 ${s.deleted}</span>
    <span class="chip chip-change">替换 ${s.changed}</span>
    <span class="chip chip-block">阻断 ${s.blocked}</span>
    <span class="chip chip-skip">跳过 ${s.skipped}</span>
    <span class="chip">未命中 ${s.unmatched}</span>
    <span class="chip">规则 ${s.rules}</span>`;
  if (data.rule_errors.length) {
    bar.innerHTML += data.rule_errors
      .map((e) => `<span class="chip chip-error">规则错误：${escapeHtml(e.rule_name)} — ${escapeHtml(e.error)}</span>`)
      .join("");
  }
  if (data.rule_stats.length) {
    const never = data.rule_stats.filter((r) => r.never_matched);
    if (never.length) {
      bar.innerHTML += `<span class="chip chip-skip" title="以下规则没有匹配到任何路径">无命中规则：${escapeHtml(
        never.map((r) => r.rule_name).join("、")
      )}</span>`;
    }
  }
}

// --------------------------------------------------------------------------- //
// Export
// --------------------------------------------------------------------------- //

async function postAndDownload(url, filename) {
  let document;
  try {
    document = readDocument();
  } catch (err) {
    $("#jsonError").textContent = "JSON 解析失败：" + err.message;
    return;
  }
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ document, rules }),
  });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    $("#jsonError").textContent = data.detail || "导出失败";
    return;
  }
  const blob = await resp.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// --------------------------------------------------------------------------- //
// Templates
// --------------------------------------------------------------------------- //

async function loadTemplates() {
  const resp = await fetch("/api/templates");
  const items = await resp.json();
  const box = $("#tplList");
  box.innerHTML = "";
  if (!items.length) {
    box.innerHTML = '<span class="hint">还没有保存过模板。</span>';
    return;
  }
  for (const t of items) {
    const row = document.createElement("div");
    row.className = "tpl-item";
    row.innerHTML = `
      <div class="tpl-meta">
        <div class="tpl-name"></div>
        <div class="tpl-desc"></div>
      </div>
      <div class="tpl-actions">
        <button class="btn btn-mini" data-act="load" type="button">加载</button>
        <button class="btn btn-mini" data-act="delete" type="button">删除</button>
      </div>`;
    row.querySelector(".tpl-name").textContent = t.name;
    row.querySelector(".tpl-desc").textContent =
      `${t.rules.length} 条规则 · ${t.description || "无说明"}`;
    row.querySelector('[data-act="load"]').addEventListener("click", () => {
      rules = t.rules.map((r) => ({
        ...r,
        id: r.id || uid(),
        enabled: r.enabled !== false,
        params: r.params || defaultParams(r.action),
      }));
      editingTemplateId = t.id;
      $("#tplName").value = t.name;
      $("#tplDesc").value = t.description;
      renderRules();
    });
    row.querySelector('[data-act="delete"]').addEventListener("click", async () => {
      if (!confirm(`确定删除模板「${t.name}」？（仅删除模板，不涉及数据）`)) return;
      await fetch(`/api/templates/${t.id}`, { method: "DELETE" });
      if (editingTemplateId === t.id) editingTemplateId = null;
      loadTemplates();
    });
    box.appendChild(row);
  }
}

async function saveTemplate() {
  const name = $("#tplName").value.trim();
  if (!name) {
    alert("请填写模板名称");
    return;
  }
  const payload = {
    name,
    description: $("#tplDesc").value.trim(),
    rules,
  };
  let resp;
  if (editingTemplateId) {
    resp = await fetch(`/api/templates/${editingTemplateId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } else {
    resp = await fetch("/api/templates", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }
  const data = await resp.json();
  if (!resp.ok) {
    alert(data.detail || "保存失败");
    return;
  }
  editingTemplateId = data.id;
  loadTemplates();
}

// --------------------------------------------------------------------------- //
// Init
// --------------------------------------------------------------------------- //

async function checkHealth() {
  try {
    const h = await (await fetch("/api/health")).json();
    const el = $("#saltStatus");
    if (h.hash_salt_configured) {
      el.textContent = "盐值：已配置 MASKING_HASH_SALT";
      el.className = "salt-status ok";
    } else {
      el.textContent = "盐值：未配置（hash 规则将报错）";
      el.className = "salt-status bad";
    }
  } catch {
    /* offline / starting */
  }
}

function wireEvents() {
  $("#btnAddRule").addEventListener("click", () => addRule());
  $("#btnPreview").addEventListener("click", runPreview);
  $("#btnSample").addEventListener("click", () => {
    $("#jsonInput").value = JSON.stringify(SAMPLE_JSON, null, 2);
    rules = SAMPLE_RULES.map((r) => ({ ...r, params: { ...r.params } }));
    renderRules();
  });
  $("#btnFormat").addEventListener("click", () => {
    try {
      $("#jsonInput").value = JSON.stringify(readDocument(), null, 2);
      $("#jsonError").textContent = "";
    } catch (err) {
      $("#jsonError").textContent = "JSON 解析失败：" + err.message;
    }
  });
  $("#btnSaveTpl").addEventListener("click", saveTemplate);
  $("#btnExportJson").addEventListener("click", () =>
    postAndDownload("/api/mask/export", "masked.json")
  );
  $("#btnExportAudit").addEventListener("click", () =>
    postAndDownload("/api/mask/audit", "audit.json")
  );
  $("#fOnlyHit").addEventListener("change", (e) => {
    showOnlyHit = e.target.checked;
    if (lastPreview) renderReport(lastPreview.groups);
  });
}

wireEvents();
rules = SAMPLE_RULES.map((r) => ({ ...r, params: { ...r.params } }));
$("#jsonInput").value = JSON.stringify(SAMPLE_JSON, null, 2);
renderRules();
loadTemplates();
checkHealth();
