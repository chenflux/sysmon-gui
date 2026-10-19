const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const state = {
  meta: { event_types: [], operators: [], eid_names: {} },
  status: null,
  isAdmin: true,
  rules: null,
  editing: null,
  editingIndex: -1,
  log: { eventId: "", keyword: "", hours: "", fetch: 1000, page: 1, pageSize: 50, data: [], total: 0, auto: false, timer: null, grouped: false, groupDims: [], openGroups: new Set(), expandedId: null, _groups: [], lastMaxRec: 0, sortKey: "time", sortDir: -1, newOnly: false },
  geo: { enabled: false, cache: {}, lastErr: 0, mmdb: null, lastStats: null },
  tree: { result: null, open: new Set() },
  applogTimer: null,
  xmlPreview: "",
};

/* ===================== 主题（暗色模式） ===================== */

function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("sysmonTheme", t); } catch (e) { }
  const b = $("#btnTheme");
  if (b) b.innerHTML = t === "dark" ? "&#9728; 浅色" : "&#9681; 深色";
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  let j = null;
  try { j = await r.json(); } catch (e) { /* ignore */ }
  if (!r.ok || (j && j.ok === false)) {
    throw new Error((j && j.error) || `HTTP ${r.status}`);
  }
  return j.data;
}

function toast(msg, type) {
  const d = document.createElement("div");
  d.className = "toast " + (type || "ok");
  d.textContent = msg;
  $("#toasts").appendChild(d);
  setTimeout(() => d.remove(), 3500);
}

function switchTab(name) {
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  $$(".tabpane").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
  if (name === "applog") loadAppLog();
  try { localStorage.setItem("sysmonGuiTab", name); } catch (e) { }
}

async function init() {
  $$(".tab").forEach((t) => t.addEventListener("click", () => switchTab(t.dataset.tab)));
  $$("[data-close]").forEach((b) => b.addEventListener("click", () => $("#" + b.dataset.close).classList.add("hidden")));
  $$(".modal").forEach((m) => m.addEventListener("click", (e) => { if (e.target === m) m.classList.add("hidden"); }));

  $("#btnInstall").addEventListener("click", () => sysmonOp("install"));
  $("#btnReinstall").addEventListener("click", () => sysmonOp("reinstall"));
  $("#btnUninstall").addEventListener("click", () => sysmonOp("uninstall"));
  $("#btnNewRule").addEventListener("click", () => openEditor(-1));
  $("#btnPreviewXml").addEventListener("click", previewXml);
  $("#btnDownloadXml").addEventListener("click", () => { window.location.href = "/api/config.xml"; });
  $("#btnRuleSave").addEventListener("click", saveEditing);
  $("#btnRulePreview").addEventListener("click", previewEditingRule);
  $("#btnXmlDownload").addEventListener("click", downloadPreviewXml);

  $("#btnQuery").addEventListener("click", () => { state.log.page = 1; loadEvents(); });
  $("#chkAuto").addEventListener("change", toggleAuto);
  $("#btnExportCsv").addEventListener("click", exportCsv);
  $("#fltKeyword").addEventListener("keydown", (e) => { if (e.key === "Enter") { state.log.page = 1; loadEvents(); } });
  $("#btnExit").addEventListener("click", shutdownApp);
  $("#btnElevate").addEventListener("click", requestElevate);
  $("#btnValidate").addEventListener("click", validateRules);
  $("#btnImport").addEventListener("click", openImportModal);
  $("#btnImportAppend").addEventListener("click", () => applyImport("append"));
  $("#btnImportReplace").addEventListener("click", () => applyImport("replace"));
  $("#btnParseXmlFile").addEventListener("click", parseXmlFile);
  $("#btnGotoStatus").addEventListener("click", () => switchTab("status"));

  $("#btnGroup").addEventListener("click", (e) => { e.stopPropagation(); $("#grpMenu").classList.toggle("hidden"); });
  document.addEventListener("click", (e) => { if (!e.target.closest("#grpDrop")) $("#grpMenu").classList.add("hidden"); });
  $$("#grpMenu .grp-opt input").forEach((c) => c.addEventListener("change", onGroupDimChange));
  $("#chkGeoIP").addEventListener("change", toggleGeoIP);
  try { state.geo.enabled = localStorage.getItem("sysmonGeoIP") === "1"; } catch (e) { }
  $("#chkGeoIP").checked = state.geo.enabled;
  if (state.geo.enabled) loadGeoStatus();
  $("#btnRuleSim").addEventListener("click", simulateRule);
  $("#btnShowDiff").addEventListener("click", showRulesDiff);
  $("#btnAppLogRefresh").addEventListener("click", loadAppLog);
  $("#btnTheme").addEventListener("click", () => applyTheme((document.documentElement.dataset.theme === "dark") ? "light" : "dark"));
  applyTheme((() => { try { return localStorage.getItem("sysmonTheme") || "light"; } catch (e) { return "light"; } })());
  $("#btnSaveFilter").addEventListener("click", saveFilterPreset);
  $("#chkNewOnly").addEventListener("change", (e) => {
    state.log.newOnly = e.target.checked;
    state.log.page = 1;
    loadEvents();
  });
  $("#chkAppLogAuto").addEventListener("change", () => {
    if (state.applogTimer) { clearInterval(state.applogTimer); state.applogTimer = null; }
    if ($("#chkAppLogAuto").checked) state.applogTimer = setInterval(() => { if (!$("#tab-applog").classList.contains("active")) return; loadAppLog(true); }, 5000);
  });
  renderPlaybooks();
  renderFilterPresets();
  $$(".evt-table th.sortable").forEach((th) => th.addEventListener("click", () => {
    const key = th.dataset.sortkey;
    if (state.log.sortKey === key) state.log.sortDir *= -1;
    else { state.log.sortKey = key; state.log.sortDir = key === "time" ? -1 : 1; }
    if (!state.log.grouped) renderEvents();
  }));
  $("#btnTreeExpandAll").addEventListener("click", () => {
    if (!state.tree.result) return;
    const guids = [];
    (function walk(n) { guids.push(n.guid); (n.children || []).forEach(walk); })(state.tree.result.root);
    state.tree.open = new Set(guids);
    renderTree(state.tree.result, true);
  });
  $("#btnTreeCollapseAll").addEventListener("click", () => {
    if (!state.tree.result) return;
    state.tree.open = new Set();
    renderTree(state.tree.result, true);
  });

  await Promise.all([loadMeta(), loadStatus(), loadRules()]);
  renderEventFilter();
  loadEvents(true);
  setInterval(loadStatus, 10000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) loadStatus(); });
  const lastTab = localStorage.getItem("sysmonGuiTab");
  if (lastTab && ["status", "rules", "logs", "applog"].includes(lastTab) && lastTab !== "status") switchTab(lastTab);
}

async function loadMeta() {
  state.meta = await api("/api/meta");
  if (state.meta.app_version) $(".brand").title = "Sysmon GUI " + state.meta.app_version;
}

async function loadStatus() {
  try {
    const d = await api("/api/status");
    state.status = d.status;
    state.isAdmin = d.is_admin;
    document.title = "Sysmon GUI " + (state.isAdmin ? "[管理员]" : "[普通权限]") + " - 部署与日志查看";
    renderStatus(d);
  } catch (e) {
    $("#topStatus").innerHTML = '<span class="dot r"></span>状态获取失败';
  }
}

let opBusy = false;

function renderStatus(d) {
  const st = d.status;
  state.rulesDirty = !!d.rules_dirty;
  const pill = st.installed
    ? (st.running ? '<span class="dot g"></span>已安装 · 运行中' : '<span class="dot y"></span>已安装 · 已停止')
    : '<span class="dot r"></span>未安装';
  $("#topStatus").innerHTML = pill + (state.isAdmin ? "" : ' <span class="dot y" title="非管理员"></span>· 非管理员');

  $("#adminBanner").classList.toggle("hidden", state.isAdmin);
  $("#sysmonMissingBanner").classList.toggle("hidden", !!st.exe_exists);
  if (!state.isAdmin && d.admin_detail) {
    const det = $("#adminDetail");
    if (det) det.textContent = ` [检测: ${d.admin_detail}]`;
  }
  $$(".dirty").forEach((b) => b.classList.toggle("hidden", !state.rulesDirty));

  const fmtSize = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : n > 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B";
  $("#statusCards").innerHTML = `
    <div class="card"><div class="k">服务状态</div><div class="v">
      ${st.installed ? '<span class="badge b-green">已安装</span>' : '<span class="badge b-red">未安装</span>'}
      ${st.installed ? (st.running ? '<span class="badge b-green">运行中</span>' : '<span class="badge b-orange">已停止</span>') : ""}
      ${st.impostor_service ? `<div class="hint" style="margin-top:6px;color:var(--warn)" title="${esc(st.impostor_service)}">&#9888; 检测到同名非 Sysmon 第三方服务，已自动忽略: ${esc(st.impostor_service)}</div>` : ""}
    </div></div>
    <div class="card"><div class="k">已安装 Sysmon 版本</div><div class="v">${esc(st.version || (st.installed ? "未知" : "未安装"))}</div></div>
    <div class="card"><div class="k">Sysmon 程序 (与本工具同目录的独立文件)</div><div class="v mono">${esc(st.exe_path)}</div>
      <div style="margin-top:6px">${st.exe_exists ? `<span class="badge b-green">文件存在</span>${st.exe_version ? `<span class="badge b-gray">v${esc(st.exe_version)}</span>` : ""}` : '<span class="badge b-red">文件缺失</span>'}</div>
      <div class="hint" style="margin-top:6px">非内嵌资源：安装/更新服务时调用此文件，随本工具目录一起分发，无需单独准备</div></div>
    <div class="card"><div class="k">配置文件 (自动生成)</div><div class="v mono">${esc(st.config_path)}</div>
      <div style="margin-top:6px">${st.config_exists
        ? `<span class="badge b-gray">${fmtSize(st.config_size)} · ${esc(st.config_mod_time)}</span>`
        : '<span class="badge b-gray">尚未生成</span>'}</div></div>
    <div class="card"><div class="k">规则数量</div><div class="v">${d.rules_enabled} 启用 / ${d.rules_total} 总计</div></div>
    <div class="card"><div class="k">本程序版本</div><div class="v mono" title="${esc(state.meta.app_version || "")}">${esc(state.meta.app_version || "dev")}</div></div>`;

  const needDisable = !state.isAdmin;
  const btnInstall = $("#btnInstall"), btnRe = $("#btnReinstall"), btnUn = $("#btnUninstall");
  btnInstall.disabled = needDisable || opBusy;
  btnRe.disabled = needDisable || opBusy || !st.installed;
  btnUn.disabled = needDisable || opBusy || !st.installed;
  btnRe.title = st.installed ? "先卸载再安装，并应用当前规则" : "Sysmon 未安装，无需重装";
  btnInstall.classList.toggle("btn-attention", state.rulesDirty && !needDisable && !opBusy);
  if (!opBusy) {
    btnInstall.innerHTML = st.installed ? "&#9654; 应用规则到 Sysmon" + (state.rulesDirty ? ' <span class="pulse-dot"></span>' : "") : "&#9654; 安装 Sysmon 并应用规则";
  }
  $("#statusHint").textContent = st.installed
    ? "「应用规则」仅更新 Sysmon 配置，不会重装服务；重新安装 = 卸载后重装"
    : "首次使用：可在「规则编辑」调整规则后，点击上方按钮一键安装";
}

async function sysmonOp(op) {
  if (opBusy) return;
  const confirms = {
    install: null,
    reinstall: "重新安装将先卸载再安装 Sysmon，并应用当前规则，继续？",
    uninstall: "确定卸载 Sysmon 吗？卸载后将停止事件采集。",
  };
  if (confirms[op] && !window.confirm(confirms[op])) return;
  opBusy = true;
  const btnInstall = $("#btnInstall");
  const labelMap = { install: st0() ? "正在应用规则…" : "正在安装…", reinstall: "正在重装…", uninstall: "正在卸载…" };
  function st0() { return state.status && state.status.installed; }
  const btns = ["btnInstall", "btnReinstall", "btnUninstall"].map((id) => $("#" + id));
  btns.forEach((b) => (b.disabled = true));
  btnInstall.innerHTML = labelMap[op] || "执行中…";
  try {
    const res = await api("/api/sysmon/" + op, { method: "POST" });
    showOpLog(res);
    toast(res.message || "操作完成", res.success ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  } finally {
    opBusy = false;
    loadStatus();
  }
}

function showOpLog(res) {
  const el = $("#opLog");
  el.classList.remove("hidden");
  const errs = res.errors || [];
  const raw = res.raw || [];
  const cfgErrs = res.config_errors || [];
  el.innerHTML = `
    <div class="op-title ${res.success ? "ok" : "err"}">${res.success ? "✔" : "✘"} ${esc(res.message)} <span style="color:#64748b">(${res.took_ms}ms)</span>
      <button class="icon-btn oplog-close" onclick="document.getElementById('opLog').classList.add('hidden')" title="收起">&times;</button></div>
    ${res.steps && res.steps.length ? "<ol>" + res.steps.map((s) => `<li>${esc(s)}</li>`).join("") + "</ol>" : ""}
    ${errs.length ? '<div class="op-errs">' + errs.map((e) => "✘ " + esc(e)).join("<br>") + "</div>" : ""}
    ${cfgErrs.length ? `
      <div class="cfg-errs">
        <div style="font-weight:700;margin:8px 0 4px">&#9888; 配置错误定位 (基于 Sysmon 官方 schema):</div>
        ${cfgErrs.map((e) => `<div class="cfg-err-line">${esc(e)} <button class="btn sm" data-fix-rule="${esc(extractRuleName(e))}">编辑此规则</button></div>`).join("")}
      </div>` : ""}
    ${raw.length ? `<details><summary>查看 Sysmon 原始命令输出 (${raw.length} 行)</summary><pre>${raw.map(esc).join("\n")}</pre></details>` : ""}`;
  el.querySelectorAll("[data-fix-rule]").forEach((b) => b.addEventListener("click", () => {
    const name = b.dataset.fixRule;
    const idx = state.rules.rules.findIndex((r) => r.name === name);
    if (idx >= 0) { switchTab("rules"); openEditor(idx); } else { toast("未找到规则「" + name + "」，可能已被删除", "err"); }
  }));
}

function extractRuleName(errText) {
  const m = errText.match(/规则\[([^\]]+)\]/);
  return m ? m[1] : "";
}

async function loadRules() {
  state.rules = await api("/api/rules");
  renderRules();
}

function opLabel(op) {
  const o = state.meta.operators.find((x) => x.op === op);
  return o ? o.label : op;
}

function summarizeRule(rule) {
  const groups = (rule.groups || []).filter((g) => g.conditions && g.conditions.length);
  if (!groups.length) return "（无条件）";
  const rel = (r) => (r === "and" ? '<b class="and">且</b>' : '<b class="or">或</b>');
  return groups
    .map((g) => {
      const inner = g.conditions
        .map((c) => `${esc(c.field)} ${esc(opLabel(c.op))} [${c.values.map(esc).join(" ; ")}]`)
        .join(" " + rel(g.relation) + " ");
      return g.conditions.length > 1 ? `(${inner})` : inner;
    })
    .join(" " + rel("or") + " ");
}

function renderRules() {
  const list = $("#rulesList");
  if (!state.rules || !state.rules.rules.length) {
    list.innerHTML = '<div class="card"><div class="empty" style="text-align:center;color:var(--muted);padding:30px">暂无规则，点击「新建规则」创建</div></div>';
    return;
  }
  const typeLabel = (t) => { const e = state.meta.event_types.find((x) => x.type === t); return e ? e.label : t; };
  list.innerHTML = state.rules.rules
    .map((r, i) => `
    <div class="rule-card ${r.enabled ? "" : "disabled-rule"}">
      <div class="rule-head">
        <label class="switch" title="${r.enabled ? "启用" : "停用"}">
          <input type="checkbox" data-toggle="${i}" ${r.enabled ? "checked" : ""}>
          <span class="slider"></span>
        </label>
        <span class="rule-name">${esc(r.name)}</span>
        <span class="badge b-purple">${esc(typeLabel(r.event_type))}</span>
        <span class="badge ${r.on_match === "include" ? "b-blue" : "b-orange"}">${r.on_match === "include" ? "记录" : "排除"}</span>
        <span class="spacer"></span>
        <button class="btn sm" data-edit="${i}">编辑</button>
        <button class="btn sm danger" data-del="${i}">删除</button>
      </div>
      ${r.note ? `<div class="rule-note">${esc(r.note)}</div>` : ""}
      <div class="rule-summary">${summarizeRule(r)}</div>
    </div>`)
    .join("");

  list.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => openEditor(+b.dataset.edit)));
  list.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
    const i = +b.dataset.del;
    if (!window.confirm(`确定删除规则「${state.rules.rules[i].name}」？`)) return;
    state.rules.rules.splice(i, 1);
    await saveRulesToServer();
  }));
  list.querySelectorAll("[data-toggle]").forEach((c) => c.addEventListener("change", async () => {
    const i = +c.dataset.toggle;
    state.rules.rules[i].enabled = c.checked;
    await saveRulesToServer();
  }));
}

async function saveRulesToServer() {
  try {
    await api("/api/rules", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(state.rules) });
    renderRules();
    loadStatus();
    return true;
  } catch (e) {
    toast("保存失败: " + e.message, "err");
    return false;
  }
}

function openEditor(index) {
  if (index >= 0) {
    state.editing = JSON.parse(JSON.stringify(state.rules.rules[index]));
    state.editingIndex = index;
    $("#ruleModalTitle").textContent = "编辑规则";
  } else {
    state.editing = { id: "r_" + Date.now(), name: "", event_type: "ProcessCreate", on_match: "include", enabled: true, note: "", groups: [{ relation: "and", conditions: [{ field: "Image", op: "contains", values: [] }] }] };
    state.editingIndex = -1;
    $("#ruleModalTitle").textContent = "新建规则";
  }
  renderEditorForm();
  $("#ruleModal").classList.remove("hidden");
}

function fieldsFor(type) {
  const e = state.meta.event_types.find((x) => x.type === type);
  return e ? e.fields : ["Image", "User"];
}

function renderEditorForm() {
  const r = state.editing;
  const typeOpts = state.meta.event_types.map((t) => `<option value="${esc(t.type)}" ${t.type === r.event_type ? "selected" : ""}>${esc(t.label)} (EID ${t.event_id})</option>`).join("");
  const fields = fieldsFor(r.event_type);
  const fieldOpts = (cur) => fields.map((f) => `<option value="${esc(f)}" ${f === cur ? "selected" : ""}>${esc(f)}</option>`).join("") + (cur && !fields.includes(cur) ? `<option value="${esc(cur)}" selected>${esc(cur)} (自定义)</option>` : "");
  const opOpts = (cur) => state.meta.operators.map((o) => `<option value="${esc(o.op)}" ${o.op === cur ? "selected" : ""}>${esc(o.label)}</option>`).join("");

  const groupsHtml = r.groups
    .map((g, gi) => `
    <div class="cond-group" data-gi="${gi}">
      <div class="group-head">
        <span class="rel-label">组内条件关系:</span>
        <select class="rel-sel" data-gr="${gi}">
          <option value="and" ${g.relation === "and" ? "selected" : ""}>与 AND（全部满足）</option>
          <option value="or" ${g.relation === "or" ? "selected" : ""}>或 OR（任一满足）</option>
        </select>
        <span class="hint">${g.relation === "and" ? "组内所有条件必须同时满足" : "组内任一条件满足即命中"}</span>
        <span class="spacer"></span>
        <button class="btn sm danger" data-delgroup="${gi}">删除组</button>
      </div>
      ${g.conditions
        .map((c, ci) => `
        <div class="cond-row">
          <select class="input" data-f="${gi}.${ci}">${fieldOpts(c.field)}</select>
          <select class="input" data-o="${gi}.${ci}">${opOpts(c.op)}</select>
          <div class="chips" data-chips="${gi}.${ci}">
            ${c.values.map((v, vi) => `<span class="chip"><span title="${esc(v)}">${esc(v)}</span><button data-rm="${gi}.${ci}.${vi}" title="移除">&times;</button></span>`).join("")}
            <input class="chip-input" data-in="${gi}.${ci}" placeholder="输入 IOC 后回车添加" list="fieldList">
          </div>
          <button class="icon-btn" data-delcond="${gi}.${ci}" title="删除条件">&times;</button>
        </div>`)
        .join("")}
      <button class="btn sm" data-addcond="${gi}">＋ 添加条件</button>
    </div>`)
    .join('<div class="group-groups-link">↑ 多个条件组之间为 <b>或</b> 关系（任一组命中即记录/排除）↓</div>');

  $("#ruleModalBody").innerHTML = `
    <datalist id="fieldList">${fields.map((f) => `<option value="${esc(f)}">`).join("")}</datalist>
    <div class="form-row">
      <div class="form-item" style="flex:2;min-width:240px"><label>规则名称 *</label><input class="input" id="edName" style="width:100%" value="${esc(r.name)}" placeholder="例：检测凭证转储工具"></div>
      <div class="form-item"><label>事件类型</label><select class="input" id="edType">${typeOpts}</select></div>
      <div class="form-item"><label>匹配方式</label>
        <select class="input" id="edOnMatch">
          <option value="include" ${r.on_match === "include" ? "selected" : ""}>记录 (命中时记录日志)</option>
          <option value="exclude" ${r.on_match === "exclude" ? "selected" : ""}>排除 (命中时不记录)</option>
        </select></div>
      <div class="form-item"><label>启用</label>
        <label class="switch" style="margin-top:8px"><input type="checkbox" id="edEnabled" ${r.enabled ? "checked" : ""}><span class="slider"></span></label></div>
    </div>
    <div class="form-row"><div class="form-item" style="flex:1"><label>备注 (可选)</label><input class="input" id="edNote" style="width:100%" value="${esc(r.note)}" placeholder="规则说明"></div></div>
    ${groupsHtml || '<div class="hint" style="padding:10px 0">尚无条件组</div>'}
    <button class="btn" id="edAddGroup">＋ 添加条件组</button>`;

  $("#edName").addEventListener("input", (e) => (state.editing.name = e.target.value));
  $("#edNote").addEventListener("input", (e) => (state.editing.note = e.target.value));
  $("#edEnabled").addEventListener("change", (e) => (state.editing.enabled = e.target.checked));
  $("#edType").addEventListener("change", (e) => { state.editing.event_type = e.target.value; renderEditorForm(); });
  $("#edOnMatch").addEventListener("change", (e) => (state.editing.on_match = e.target.value));
  $("#edAddGroup").addEventListener("click", () => { state.editing.groups.push({ relation: "and", conditions: [{ field: fieldsFor(state.editing.event_type)[0], op: "contains", values: [] }] }); renderEditorForm(); });

  const body = $("#ruleModalBody");
  body.querySelectorAll("[data-gr]").forEach((s) => s.addEventListener("change", () => { state.editing.groups[+s.dataset.gr].relation = s.value; renderEditorForm(); }));
  body.querySelectorAll("[data-delgroup]").forEach((b) => b.addEventListener("click", () => { state.editing.groups.splice(+b.dataset.delgroup, 1); renderEditorForm(); }));
  body.querySelectorAll("[data-addcond]").forEach((b) => b.addEventListener("click", () => { state.editing.groups[+b.dataset.addcond].conditions.push({ field: fieldsFor(state.editing.event_type)[0], op: "contains", values: [] }); renderEditorForm(); }));
  body.querySelectorAll("[data-delcond]").forEach((b) => b.addEventListener("click", () => { const [gi, ci] = b.dataset.delcond.split(".").map(Number); state.editing.groups[gi].conditions.splice(ci, 1); renderEditorForm(); }));
  body.querySelectorAll("[data-f]").forEach((s) => s.addEventListener("change", () => { const [gi, ci] = s.dataset.f.split(".").map(Number); state.editing.groups[gi].conditions[ci].field = s.value; }));
  body.querySelectorAll("[data-o]").forEach((s) => s.addEventListener("change", () => { const [gi, ci] = s.dataset.o.split(".").map(Number); state.editing.groups[gi].conditions[ci].op = s.value; }));
  body.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => {
    const [gi, ci, vi] = b.dataset.rm.split(".").map(Number);
    state.editing.groups[gi].conditions[ci].values.splice(vi, 1);
    renderEditorForm();
  }));
  body.querySelectorAll(".chip-input").forEach((inp) => {
    inp.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === ",") {
        e.preventDefault();
        addChipValue(inp, inp.value);
      } else if (e.key === "Backspace" && inp.value === "") {
        const [gi, ci] = inp.dataset.in.split(".").map(Number);
        const vals = state.editing.groups[gi].conditions[ci].values;
        if (vals.length) { vals.pop(); renderEditorForm(); focusChipInput(gi, ci); }
      }
    });
    inp.addEventListener("blur", () => { if (inp.value.trim()) addChipValue(inp, inp.value); });
  });
}

function addChipValue(inp, raw) {
  const [gi, ci] = inp.dataset.in.split(".").map(Number);
  const parts = raw.split(/[;\n]/).map((s) => s.trim()).filter(Boolean);
  if (!parts.length) return;
  const cond = state.editing.groups[gi].conditions[ci];
  for (const p of parts) if (!cond.values.includes(p)) cond.values.push(p);
  renderEditorForm();
  focusChipInput(gi, ci);
}

function focusChipInput(gi, ci) {
  const inp = $(`#ruleModalBody [data-in="${gi}.${ci}"]`);
  if (inp) inp.focus();
}

function validateEditing() {
  const r = state.editing;
  if (!r.name.trim()) return "规则名称不能为空";
  let conds = 0;
  for (const g of r.groups) {
    for (const c of g.conditions) {
      if (!c.field) return "存在未选择字段的条件";
      if (!c.values.length) return `条件「${c.field}」至少需要一个 IOC 值`;
      if (c.values.some((v) => v.includes(";"))) return `条件「${c.field}」的值不能包含分号`;
      conds++;
    }
  }
  if (!conds) return "至少需要一个条件";
  return null;
}

async function saveEditing() {
  const err = validateEditing();
  if (err) { toast(err, "err"); return; }
  if (state.editingIndex >= 0) state.rules.rules[state.editingIndex] = state.editing;
  else state.rules.rules.push(state.editing);
  if (await saveRulesToServer()) {
    $("#ruleModal").classList.add("hidden");
    toast("规则已保存（尚未部署到系统，可点击「保存并部署」或状态页安装）");
  }
}

async function previewXml() {
  try {
    const d = await api("/api/rules/preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(state.rules) });
    showXml(d.xml, "完整配置 XML（当前已保存的全部规则）");
  } catch (e) { toast(e.message, "err"); }
}

async function previewEditingRule() {
  const err = validateEditing();
  if (err) { toast(err, "err"); return; }
  const only = JSON.parse(JSON.stringify(state.editing));
  only.enabled = true;
  const tmp = JSON.parse(JSON.stringify(state.rules));
  tmp.rules = [only];
  try {
    const d = await api("/api/rules/preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(tmp) });
    showXml(d.xml, "当前规则 XML（仅此规则，非完整配置）");
  } catch (e) { toast(e.message, "err"); }
}

function showXml(xml, title) {
  state.xmlPreview = xml;
  $("#xmlPre").textContent = xml;
  $("#xmlModalTitle").textContent = title || "Sysmon 配置 XML 预览";
  $("#xmlModal").classList.remove("hidden");
}

function downloadPreviewXml() {
  const blob = new Blob([state.xmlPreview], { type: "application/xml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "sysmon-config.xml";
  a.click();
  URL.revokeObjectURL(a.href);
}

async function deploy() {
  if (!(await saveRulesToServer())) return;
  toast("规则已保存，正在部署…");
  switchTab("status");
  await sysmonOp("install");
}function renderEventFilter() {
  const opts = ['<option value="">全部事件类型</option>']
    .concat(state.meta.event_types.map((t) => `<option value="${t.event_id}">EID ${t.event_id} ${esc(t.label)}</option>`))
    .join("");
  $("#fltEvent").innerHTML = opts;
  $("#fltEvent").addEventListener("change", (e) => { state.log.eventId = e.target.value; state.log.page = 1; loadEvents(); });
  $("#fltHours").addEventListener("change", (e) => { state.log.hours = e.target.value; state.log.page = 1; });
  $("#fltFetch").addEventListener("change", (e) => { state.log.fetch = +e.target.value; });
  $("#fltKeyword").addEventListener("input", (e) => { state.log.keyword = e.target.value; });
}

async function loadEvents(silent, forceFull) {
  const p = new URLSearchParams();
  if (state.log.eventId) p.set("event_id", state.log.eventId);
  if (state.log.keyword.trim()) p.set("keyword", state.log.keyword.trim());
  if (state.log.hours) p.set("hours", state.log.hours);
  p.set("fetch", state.log.fetch);
  state.log.grouped = state.log.groupDims.length > 0;
  // 自动刷新 + 第 1 页（或分组视图）时按 record_id 游标增量拉取，避免周期性全量扫描
  const canInc = !!silent && !forceFull && state.log.auto && state.log.lastMaxRec > 0 && (state.log.grouped || state.log.page === 1) && !state.log.newOnly;
  try {
    let d;
    if (canInc) {
      p.set("since_record_id", state.log.lastMaxRec);
      p.set("page", 1);
      p.set("page_size", 200);
      d = await api("/api/events?" + p.toString());
      const fresh = d.events || [];
      if (fresh.length >= 200) {
        return await loadEvents(false, true);
      }
      if (!fresh.length) { updateNewOnlyBar(); return; }
      const seen = new Set(state.log.data.map((e) => e.record_id));
      const add = fresh.filter((e) => !seen.has(e.record_id));
      if (!add.length) return;
      state.log.data = add.concat(state.log.data).slice(0, Math.max(state.log.fetch, state.log.pageSize));
      state.log.total += add.length;
      for (const e of fresh) if (e.record_id > state.log.lastMaxRec) state.log.lastMaxRec = e.record_id;
      finishEventsLoad();
      return;
    }
    if (state.log.grouped) {
      // 分组视图需要整个窗口的内存数据，一次性拉全量（原生 API 上限 10 万）
      p.set("page", 1);
      p.set("page_size", state.log.fetch);
    } else {
      p.set("page", state.log.page);
      p.set("page_size", state.log.pageSize);
    }
    if (!silent) $("#evtBody").innerHTML = '<tr><td colspan="4" class="empty">查询中…</td></tr>';
    d = await api("/api/events?" + p.toString());
    state.log.data = d.events || [];
    state.log.total = d.total;
    state.log.lastMaxRec = 0;
    for (const e of state.log.data) if (e.record_id > state.log.lastMaxRec) state.log.lastMaxRec = e.record_id;
    finishEventsLoad();
  } catch (e) {
    $("#evtBody").innerHTML = `<tr><td colspan="4" class="empty">${esc(e.message)}</td></tr>`;
    $("#evtPager").innerHTML = "";
  }
}

// 数据就绪后的公共收尾：只看新事件过滤 + 渲染
function finishEventsLoad() {
  if (state.log.newOnly) {
    const mark = +(localStorage.getItem("sysmonReadMark") || 0);
    state.log.data = state.log.data.filter((e) => e.record_id > mark);
  }
  updateNewOnlyBar();
  if (state.log.grouped) renderGroupedEvents(); else renderEvents();
  renderGeoPanel();
}

function updateNewOnlyBar() {
  const bar = $("#newonlyBar");
  if (!state.log.newOnly) { bar.classList.add("hidden"); return; }
  const mark = +(localStorage.getItem("sysmonReadMark") || 0);
  const n = state.log.data.length;
  bar.classList.remove("hidden");
  bar.innerHTML = `<span class="hint">&#128276; 只看新事件：基准 RecordID ${mark} · 当前窗口 ${n} 条新事件</span>
    <button class="btn sm" id="btnMarkRead" ${state.log.lastMaxRec <= mark ? "disabled" : ""}>标记为已读</button>`;
  const b = $("#btnMarkRead");
  if (b) b.addEventListener("click", () => {
    try { localStorage.setItem("sysmonReadMark", String(state.log.lastMaxRec)); } catch (e) { }
    toast("已标记为已读，后续仅显示更新的事件");
    loadEvents();
  });
}

function fmtTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  const pad = (n, w) => String(n).padStart(w || 2, "0");
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

function dataMap(ev) {
  const m = {};
  for (const kv of ev.data || []) m[kv.name] = kv.value;
  return m;
}

function baseName(p) {
  if (!p) return "";
  return p.split("\\").pop().split("/").pop();
}

function eventSummary(ev) {
  const d = dataMap(ev);
  const seg = (s) => `<span>${esc(s)}</span>`;
  switch (ev.event_id) {
    case 1: return `${esc(baseName(d.Image))} <span class="lbl">命令行:</span> ${seg(d.CommandLine || "-")}`;
    case 2: return `${seg(d.TargetFilename || "-")} <span class="lbl">由</span> ${esc(baseName(d.Image))}`;
    case 3: return `${esc(baseName(d.Image))} <span class="lbl">→</span> ${esc(d.DestinationIp || "-")}:${esc(d.DestinationPort || "-")} <span class="lbl">(${esc(d.Protocol || "")})</span>`;
    case 5: return `${seg(d.Image || "-")} <span class="lbl">PID ${esc(d.ProcessId || "-")}</span>`;
    case 6: case 7: return `${seg(d.ImageLoaded || "-")} ${d.Signed === "false" ? '<span class="badge b-red">未签名</span>' : ""}`;
    case 8: return `${esc(baseName(d.SourceImage))} <span class="lbl">→</span> ${esc(baseName(d.TargetImage))}`;
    case 9: return `${esc(baseName(d.Image))} <span class="lbl">读取设备</span> ${esc(d.Device || "-")}`;
    case 10: return `${esc(baseName(d.SourceImage))} <span class="lbl">→</span> ${esc(baseName(d.TargetImage))} <span class="lbl">权限</span> ${esc(d.GrantedAccess || "-")}`;
    case 11: case 15: case 23: case 26: return `${seg(d.TargetFilename || "-")} <span class="lbl">由</span> ${esc(baseName(d.Image))}`;
    case 12: case 13: case 14: return `${seg(d.TargetObject || "-")} <span class="lbl">由</span> ${esc(baseName(d.Image))}`;
    case 17: case 18: return `${seg(d.PipeName || "-")} <span class="lbl">由</span> ${esc(baseName(d.Image))}`;
    case 22: return `${esc(baseName(d.Image))} <span class="lbl">查询</span> ${esc(d.QueryName || "-")}`;
    case 25: return `${seg(d.Image || "-")} <span class="lbl">PID ${esc(d.ProcessId || "-")}</span>`;
    default: {
      const parts = (ev.data || []).slice(0, 2).filter((kv) => kv.value).map((kv) => `${esc(kv.name)}=${esc(kv.value)}`);
      return parts.join(" ") || "-";
    }
  }
}

const FILTERABLE_FIELDS = ["Image", "ParentImage", "SourceImage", "TargetImage", "ProcessGuid", "QueryName", "TargetFilename", "PipeName", "TargetObject", "CommandLine", "User", "ImageLoaded", "DestinationIp", "DestinationHostname", "Signature", "Company"];
const VT_FIELDS = ["DestinationIp", "SourceIp", "QueryName", "DestinationHostname"];
const GUID_FIELDS = { ProcessGuid: "ProcessGuid", SourceProcessGuid: "SourceProcessGuid", TargetProcessGuid: "TargetProcessGuid", ProcessId: "ProcessGuid", SourceProcessId: "SourceProcessGuid", TargetProcessId: "TargetProcessGuid" };
const GEO_IP_FIELDS = ["DestinationIp", "SourceIp"];
const IP_LIKE = /^[0-9a-fA-F.:]+$/;

function detailRow(kv, ev) {
  let actions = "";
  const guidField = GUID_FIELDS[kv.name];
  if (guidField && kv.value) {
    const guid = guidField === kv.name ? kv.value : (dataMap(ev)[guidField] || "");
    if (guid) {
      actions += `<button class="btn sm act-btn" data-tree="${esc(guid)}" title="查看该进程的谱系树（父进程链 / 全部关联事件 / 子进程链）">&#127795;</button>`;
    }
  }
  if (FILTERABLE_FIELDS.includes(kv.name) && kv.value) {
    actions += `<button class="btn sm act-btn" data-filter="${esc(kv.value)}" title="按此值筛选日志">&#128269;</button>`;
  }
  if (kv.name === "Hashes" && kv.value) {
    for (const m of kv.value.matchAll(/(MD5|SHA1|SHA256|IMPHASH)=([0-9A-Fa-f]+)/g)) {
      actions += ` <a class="btn sm act-btn" href="https://www.virustotal.com/gui/search/${m[2]}" target="_blank" rel="noopener" title="VirusTotal 检索 ${m[1]}">VT</a>`;
    }
  } else if (VT_FIELDS.includes(kv.name) && kv.value) {
    actions += ` <a class="btn sm act-btn" href="https://www.virustotal.com/gui/search/${encodeURIComponent(kv.value)}" target="_blank" rel="noopener" title="VirusTotal 检索">VT &#8599;</a>`;
  }
  let geo = "";
  if (state.geo.enabled && GEO_IP_FIELDS.includes(kv.name) && kv.value && IP_LIKE.test(kv.value)) {
    geo = ` <span class="geo-badge" data-geoip="${esc(kv.value)}"></span>`;
  }
  return `<div class="dk">${esc(kv.name)}</div><div class="dv">${esc(kv.value)}${geo}${actions}</div>`;
}

function detailContentHtml(ev, i) {
  return `
    <div class="detail-grid">
      ${(ev.data || []).map((kv) => detailRow(kv, ev)).join("")}
    </div>
    <div class="detail-actions">
      <button class="btn sm" data-copy="${i}">复制 JSON</button>
      ${ev.record_id ? `<button class="btn sm" data-xml="${ev.record_id}" title="查看该事件的原始 XML（原生 API 拉取过的事件可查）">查看 XML</button>` : ""}
      <span class="hint">RecordID: ${ev.record_id} · 计算机: ${esc(ev.computer)}</span>
    </div>`;
}

function eventRowHtml(ev, i, withDetail) {
  const eidName = state.meta.eid_names[ev.event_id] || "未知";
  const row = `
    <tr class="row" data-evt="${i}">
      <td class="evt-time">${esc(fmtTime(ev.time))}</td>
      <td class="evt-id"><span class="eid-badge ${eidClsName(ev.event_id)}" title="${esc(eidName)}">${ev.event_id}</span></td>
      <td class="evt-type">${esc(eidName)}</td>
      <td class="evt-sum">${eventSummary(ev)}</td>
    </tr>`;
  if (withDetail === false) return row;
  return row + `
    <tr class="detail-row" data-detail="${i}" style="display:none">
      <td colspan="4">${detailContentHtml(ev, i)}</td>
    </tr>`;
}

function bindEventRows(scope) {
  scope.querySelectorAll("tr.row[data-evt]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const i = +tr.dataset.evt;
      const ev = state.log.data[i];
      let d = tr.nextElementSibling;
      if (!d || !d.classList.contains("detail-row")) {
        // 分组视图：按需创建详情行，避免一次性渲染全窗口详情
        d = document.createElement("tr");
        d.className = "detail-row";
        d.style.display = "none";
        d.innerHTML = `<td colspan="4">${detailContentHtml(ev, i)}</td>`;
        tr.after(d);
        bindDetailRow(d);
      }
      const willShow = d.style.display === "none";
      $$("#evtBody .detail-row").forEach((x) => (x.style.display = "none"));
      d.style.display = willShow ? "" : "none";
      state.log.expandedId = willShow ? (ev.record_id || null) : null;
      if (willShow) fillGeoBadges(d);
    });
  });
  scope.querySelectorAll("tr.detail-row[data-detail]").forEach((d) => bindDetailRow(d));
}

function bindDetailRow(d) {
  d.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", (e) => {
    e.stopPropagation();
    const ev = state.log.data[+b.dataset.copy];
    navigator.clipboard.writeText(JSON.stringify(ev, null, 2)).then(() => toast("已复制 JSON"), () => toast("复制失败", "err"));
  }));
  d.querySelectorAll("[data-filter]").forEach((b) => b.addEventListener("click", (e) => {
    e.stopPropagation();
    state.log.keyword = b.dataset.filter;
    $("#fltKeyword").value = state.log.keyword;
    state.log.page = 1;
    loadEvents();
    toast("已按 " + (b.dataset.filter.length > 40 ? b.dataset.filter.slice(0, 40) + "…" : b.dataset.filter) + " 筛选");
  }));
  d.querySelectorAll("[data-tree]").forEach((b) => b.addEventListener("click", (e) => {
    e.stopPropagation();
    openTree(b.dataset.tree);
  }));
  d.querySelectorAll("[data-xml]").forEach((b) => b.addEventListener("click", (e) => {
    e.stopPropagation();
    const id = b.dataset.xml;
    b.disabled = true;
    fetch("/api/events/xml?record_id=" + id)
      .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.text(); })
      .then((t) => { showXml(t, "事件原始 XML (RecordID " + id + ")"); })
      .catch((err) => toast("获取 XML 失败: " + err.message + "（可能不在缓存中，重新查询后再试）", "err"))
      .finally(() => { b.disabled = false; });
  }));
  fillGeoBadges(d);
}

function sortedIndices(data) {
  const idx = data.map((_, i) => i);
  const { sortKey, sortDir } = state.log;
  idx.sort((a, b) => {
    let r;
    if (sortKey === "event_id") {
      r = data[a].event_id - data[b].event_id;
    } else {
      const ta = Date.parse(data[a].time) || 0, tb = Date.parse(data[b].time) || 0;
      r = ta - tb;
    }
    return r * sortDir;
  });
  return idx;
}

function updateSortIndicators() {
  $$(".evt-table th.sortable").forEach((th) => {
    const ind = th.querySelector(".sort-ind");
    if (!ind) return;
    if (th.dataset.sortkey === state.log.sortKey) {
      ind.textContent = state.log.sortDir === 1 ? "▲" : "▼";
      th.classList.add("active");
    } else {
      ind.textContent = "";
      th.classList.remove("active");
    }
  });
}

function renderEvents() {
  const { data, total, page, pageSize } = state.log;
  updateSortIndicators();
  if (!data.length) {
    $("#evtBody").innerHTML = '<tr><td colspan="4" class="empty">无匹配事件</td></tr>';
  } else {
    $("#evtBody").innerHTML = sortedIndices(data).map((i) => eventRowHtml(data[i], i)).join("");
    bindEventRows($("#evtBody"));
    if (state.log.expandedId != null) {
      const idx = data.findIndex((ev) => ev.record_id === state.log.expandedId);
      if (idx >= 0) {
        const d = $(`#evtBody [data-detail="${idx}"]`);
        if (d) d.style.display = "";
      }
    }
  }

  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  $("#evtPager").innerHTML = `
    <span>共 ${total} 条 · 第 ${from}-${to} 条 · 页 ${page}/${pages}</span>
    <button class="btn sm" id="pgPrev" ${page <= 1 ? "disabled" : ""}>‹ 上一页</button>
    <button class="btn sm" id="pgNext" ${page >= pages ? "disabled" : ""}>下一页 ›</button>`;
  const prev = $("#pgPrev"), next = $("#pgNext");
  if (prev) prev.addEventListener("click", () => { state.log.page--; loadEvents(true, true); });
  if (next) next.addEventListener("click", () => { state.log.page++; loadEvents(true, true); });
}

function toggleAuto() {
  state.log.auto = $("#chkAuto").checked;
  if (state.log.timer) { clearInterval(state.log.timer); state.log.timer = null; }
  if (state.log.auto) {
    state.log.timer = setInterval(() => loadEvents(true), 5000);
    toast("已开启自动刷新 (5s)");
  }
}

function exportCsv() {
  const p = new URLSearchParams();
  if (state.log.eventId) p.set("event_id", state.log.eventId);
  if (state.log.keyword.trim()) p.set("keyword", state.log.keyword.trim());
  if (state.log.hours) p.set("hours", state.log.hours);
  p.set("fetch", state.log.fetch);
  window.location.href = "/api/events.csv?" + p.toString();
}

async function shutdownApp() {
  if (!window.confirm("确定退出 Sysmon GUI 吗？\n退出后仅关闭本管理程序，Sysmon 服务（若已安装）不受影响继续运行。")) return;
  try { await api("/api/shutdown", { method: "POST" }); } catch (e) { /* 进程已退出 */ }
  document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-size:15px;color:#64748b;background:#f1f5f9">Sysmon GUI 已退出，可以关闭此页面。</div>';
}

async function requestElevate() {
  try {
    const d = await api("/api/elevate", { method: "POST" });
    if ((d.message || "").indexOf("已是") !== -1) {
      toast(d.message + "，正在刷新状态显示…");
      await loadStatus();
      return;
    }
    toast(d.message || "已弹出 UAC 授权窗口");
    let n = 0;
    const timer = setInterval(async () => {
      n++;
      try {
        await api("/api/status");
        clearInterval(timer);
        location.reload();
      } catch (e) {
        if (n > 40) clearInterval(timer);
      }
    }, 1000);
  } catch (e) {
    toast(e.message, "err");
  }
}

function showResult(title, text) {
  $("#resultModalTitle").textContent = title;
  $("#resultPre").textContent = text;
  $("#resultModal").classList.remove("hidden");
}

let pendingImport = null;
let pendingDupCount = 0;

function openImportModal() {
  pendingImport = null;
  pendingDupCount = 0;
  $("#importPreview").classList.add("hidden");
  $("#importPreview").innerHTML = "";
  $("#btnImportAppend").disabled = true;
  $("#btnImportReplace").disabled = true;
  $("#importXmlFile").value = "";
  loadTemplates();
  $("#importModal").classList.remove("hidden");
}

async function loadTemplates() {
  const box = $("#tplList");
  box.innerHTML = '<span class="hint">加载模板列表…</span>';
  try {
    const list = await api("/api/templates");
    if (!list.length) { box.innerHTML = '<span class="hint">无内置模板</span>'; return; }
    box.innerHTML = list.map((t) => `
      <div class="tpl-item ${t.available ? "" : "disabled"}">
        <div class="tpl-info">
          <div class="tpl-name">${esc(t.name)} ${t.available ? "" : '<span class="badge b-red">文件缺失</span>'}</div>
          <div class="tpl-desc">${esc(t.description)}</div>
        </div>
        <button class="btn sm primary" data-tpl="${esc(t.id)}" ${t.available ? "" : "disabled"}>导入</button>
      </div>`).join("");
    box.querySelectorAll("[data-tpl]").forEach((b) => b.addEventListener("click", () => importTemplate(b.dataset.tpl)));
  } catch (e) {
    box.innerHTML = `<span class="hint" style="color:var(--danger)">${esc(e.message)}</span>`;
  }
}

async function importTemplate(id) {
  try {
    const d = await api("/api/templates/" + encodeURIComponent(id));
    showImportPreview(d);
  } catch (e) { toast(e.message, "err"); }
}

async function parseXmlFile() {
  const f = $("#importXmlFile").files[0];
  if (!f) { toast("请先选择 XML 文件", "err"); return; }
  const text = await f.text();
  try {
    const d = await api("/api/rules/import-xml", { method: "POST", headers: { "Content-Type": "application/xml" }, body: text });
    showImportPreview(d);
  } catch (e) { toast("解析失败: " + e.message, "err"); }
}

function ruleFingerprint(r) {
  const groups = (r.groups || [])
    .map((g) => g.relation + ":" + (g.conditions || [])
      .map((c) => c.field + "|" + c.op + "|" + (c.values || []).slice().sort().join(","))
      .sort().join(";"))
    .sort().join("||");
  return r.event_type + "|" + r.on_match + "|" + groups;
}

function countDuplicates(importRules, existingRules) {
  const seen = new Set(existingRules.map(ruleFingerprint));
  let n = 0;
  for (const r of importRules) if (seen.has(ruleFingerprint(r))) n++;
  return n;
}

function showImportPreview(d) {
  pendingImport = d.config;
  const errs = (d.lint && d.lint.errors) || [];
  const warns = (d.lint && d.lint.warnings) || [];
  const dupCount = countDuplicates(d.config.rules || [], state.rules.rules || []);
  pendingDupCount = dupCount;
  $("#importPreview").classList.remove("hidden");
  $("#importPreview").innerHTML = `
    <div class="import-stats">
      <span class="badge b-blue">${d.rules_total} 条规则</span>
      <span class="badge b-green">${d.rules_enabled} 条启用</span>
      <span class="badge b-gray">${d.cond_total} 个条件</span>
      ${dupCount > 0 ? `<span class="badge b-orange">${dupCount} 条与现有重复 (追加时跳过)</span>` : ""}
      ${errs.length ? `<span class="badge b-red">${errs.length} 个错误</span>` : '<span class="badge b-green">校验无错误</span>'}
      ${warns.length ? `<span class="badge b-orange">${warns.length} 个警告</span>` : ""}
    </div>
    ${errs.length ? '<div class="import-lint" style="color:var(--danger)">' + errs.slice(0, 5).map(esc).join("<br>") + (errs.length > 5 ? `<br>… 共 ${errs.length} 个` : "") + "</div>" : ""}
    ${warns.length ? '<div class="import-lint" style="color:var(--warn)">' + warns.slice(0, 3).map(esc).join("<br>") + (warns.length > 3 ? `<br>… 共 ${warns.length} 个` : "") + "</div>" : ""}`;
  $("#btnImportAppend").disabled = false;
  $("#btnImportReplace").disabled = false;
}

async function applyImport(mode) {
  if (!pendingImport) return;
  if (mode === "replace" && !window.confirm(`确定用导入的 ${pendingImport.rules.length} 条规则替换现有全部 ${state.rules.rules.length} 条规则吗？`)) return;
  if (mode === "append") {
    const seen = new Set(state.rules.rules.map(ruleFingerprint));
    const added = [];
    for (const r of pendingImport.rules) {
      if (seen.has(ruleFingerprint(r))) continue;
      r.id = "r_" + Date.now() + "_" + Math.floor(Math.random() * 1e6);
      seen.add(ruleFingerprint(r));
      added.push(r);
    }
    if (!added.length) {
      toast(`导入的 ${pendingImport.rules.length} 条规则全部与现有规则重复，未做更改`, "err");
      $("#importModal").classList.add("hidden");
      return;
    }
    state.rules.rules = state.rules.rules.concat(added);
    if (pendingImport.schema_version) state.rules.schema_version = pendingImport.schema_version;
    if (pendingImport.hash_algorithms) state.rules.hash_algorithms = pendingImport.hash_algorithms;
    state.rules.dns_lookup = pendingImport.dns_lookup;
    pendingImport.rules = added;
  } else {
    state.rules = pendingImport;
  }
  $("#importModal").classList.add("hidden");
  if (await saveRulesToServer()) {
    const skipped = mode === "append" && pendingDupCount > 0 ? `，跳过 ${pendingDupCount} 条重复` : "";
    toast(`导入完成（${pendingImport.rules.length} 条${skipped}），记得「保存并部署」生效`);
  }
}

async function validateRules() {
  try {
    const d = await api("/api/rules/validate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(state.rules) });
    const errs = (d.issues && d.issues.errors) || [];
    const warns = (d.issues && d.issues.warnings) || [];
    let msg = `启用规则 ${d.rules_total} 条 / ${d.groups_total} 个规则组\nXML 语法: ${d.xml_well_formed ? "正确 ✔" : "错误 ✘"}\n`;
    if (!errs.length && !warns.length) {
      msg += "\n✔ 未发现问题。\n\n注：静态校验不调用 Sysmon，最终以部署时 Sysmon 的解析结果为准。";
      toast("规则校验通过");
    } else {
      if (errs.length) msg += `\n✘ 错误 (${errs.length}):\n` + errs.map((s) => "  · " + s).join("\n");
      if (warns.length) msg += `\n⚠ 警告 (${warns.length}):\n` + warns.map((s) => "  · " + s).join("\n");
      msg += "\n\n注：部分署时 Sysmon 会做最终校验，配置解析失败不会影响现有配置。";
    }
    showResult("规则校验结果", msg);
  } catch (e) {
    toast("校验失败: " + e.message, "err");
  }
}

/* ===================== EID 彩色徽标 ===================== */

const EID_CLS = { 1: "proc", 5: "proc", 25: "proc", 3: "net", 22: "dns", 2: "file", 11: "file", 15: "file", 23: "file", 26: "file", 27: "file", 28: "file", 29: "file", 12: "reg", 13: "reg", 14: "reg", 8: "inj", 10: "inj", 9: "inj", 17: "pipe", 18: "pipe", 6: "drv", 7: "img", 19: "wmi", 20: "wmi", 21: "wmi" };
function eidClsName(id) { return "eid-" + (EID_CLS[id] || "oth"); }

/* ===================== P1: 进程谱系树 ===================== */

async function openTree(guid) {
  $("#treeModalTitle").textContent = "进程谱系";
  $("#treeBody").innerHTML = `<div class="empty" style="text-align:center;color:var(--muted);padding:40px">正在构建谱系（扫描 ${state.log.fetch} 条事件窗口）…</div>`;
  $("#treeHint").textContent = "";
  $("#treeModal").classList.remove("hidden");
  try {
    const p = new URLSearchParams({ guid, fetch: state.log.fetch });
    if (state.log.hours) p.set("hours", state.log.hours);
    const d = await api("/api/events/process-tree?" + p.toString());
    state.tree.result = d;
    renderTree(d, false);
  } catch (e) {
    $("#treeBody").innerHTML = `<div class="empty" style="text-align:center;color:var(--danger);padding:40px">${esc(e.message)}</div>`;
  }
}

function findTreeNode(n, guid) {
  if (n.guid === guid) return n;
  for (const c of n.children || []) {
    const r = findTreeNode(c, guid);
    if (r) return r;
  }
  return null;
}

function treeChainSet(d) {
  const byGuid = new Map();
  (function walk(n) { byGuid.set(n.guid, n); (n.children || []).forEach(walk); })(d.root);
  const chain = new Set();
  let cur = byGuid.get(d.focus_guid);
  while (cur) {
    chain.add(cur.guid);
    cur = cur.parent_guid ? byGuid.get(cur.parent_guid) : null;
  }
  return chain;
}

function nodeInnerHtml(n, d) {
  let html = (n.events || []).map((t) => `
    <div class="pt-ev">
      <span class="pt-ev-time">${esc(fmtTime(t.time))}</span>
      <span class="eid-badge ${eidClsName(t.event_id)}" title="${esc(state.meta.eid_names[t.event_id] || "")}">${t.event_id}</span>
      <span class="pt-ev-sum">${eventSummary({ event_id: t.event_id, data: t.data })}</span>
    </div>`).join("");
  if (n.events_truncated) {
    html += `<div class="pt-ev-more">… 该进程事件过多，仅显示前 ${n.events.length} 条（共 ${n.event_count} 条），点击节点 &#128269; 在日志中查看全部</div>`;
  }
  html += (n.children || []).map((c) => nodeHtml(c, d)).join("");
  return html;
}

function nodeHtml(n, d) {
  const isFocus = n.guid === d.focus_guid;
  const hasBody = (n.children && n.children.length) || (n.events && n.events.length);
  const open = state.tree.open.has(n.guid);
  const evCount = n.event_count || (n.events ? n.events.length : 0);
  let html = `
    <div class="pt-head ${isFocus ? "focus" : ""}">
      <button class="pt-caret" data-ptg="${esc(n.guid)}" title="折叠/展开">${hasBody ? (open ? "&#9662;" : "&#9656;") : "&#183;"}</button>
      <span class="pt-img" title="${esc(n.image || n.guid)}">${esc(baseName(n.image) || n.guid)}</span>
      ${n.process_id ? `<span class="pt-pid">PID ${esc(n.process_id)}</span>` : ""}
      ${n.user ? `<span class="pt-user" title="${esc(n.user)}">${esc(n.user)}</span>` : ""}
      ${n.start_time ? `<span class="pt-time">${esc(fmtTime(n.start_time))}</span>` : ""}
      ${n.synthetic ? '<span class="badge b-orange" title="该进程的启动事件 (EID 1) 不在当前窗口内，父进程链缺失">窗口外</span>' : ""}
      ${isFocus ? '<span class="badge b-blue">当前进程</span>' : ""}
      ${(n.children && n.children.length) ? `<span class="badge b-gray">子进程 ${n.children.length}</span>` : ""}
      ${evCount ? `<span class="badge b-gray">事件 ${evCount}</span>` : ""}
      <button class="btn sm act-btn" data-filter="${esc(n.guid)}" title="在日志列表中筛选该进程的全部事件">&#128269;</button>
    </div>`;
  if (n.command_line && n.command_line !== n.image) {
    html += `<div class="pt-cmd" title="${esc(n.command_line)}">${esc(n.command_line)}</div>`;
  }
  if (hasBody && open) {
    html += `<div class="pt-body">${nodeInnerHtml(n, d)}</div>`;
  }
  return `<div class="pt-node ${isFocus ? "focus" : ""}" data-guid="${esc(n.guid)}">${html}</div>`;
}

function renderTree(d, keepOpen) {
  if (!keepOpen) state.tree.open = treeChainSet(d);
  const focusNode = findTreeNode(d.root, d.focus_guid);
  $("#treeModalTitle").textContent = "进程谱系 — " + (baseName(focusNode ? focusNode.image : "") || d.focus_guid) + (d.focus_pid ? ` (PID ${d.focus_pid})` : "");
  $("#treeHint").textContent = `窗口内 ${d.scanned}/${d.fetch} 条事件${d.truncated ? " · 已达加载上限，谱系可能不完整" : ""} · 窗口外启动的进程父链缺失，显示为根节点`;
  $("#treeBody").innerHTML = `<div class="pt-tree">${nodeHtml(d.root, d)}</div>`;
  bindTreeNodes($("#treeBody"));
}

function bindTreeNodes(scope) {
  scope.querySelectorAll(".pt-caret[data-ptg]").forEach((b) => b.addEventListener("click", (e) => {
    e.stopPropagation();
    const nodeEl = b.closest(".pt-node");
    const guid = b.dataset.ptg;
    if (state.tree.open.has(guid)) {
      state.tree.open.delete(guid);
      const bodyEl = nodeEl.querySelector(":scope > .pt-body");
      if (bodyEl) bodyEl.remove();
      b.innerHTML = "&#9656;";
    } else {
      state.tree.open.add(guid);
      let bodyEl = nodeEl.querySelector(":scope > .pt-body");
      if (!bodyEl) {
        bodyEl = document.createElement("div");
        bodyEl.className = "pt-body";
        nodeEl.appendChild(bodyEl);
      }
      bodyEl.innerHTML = nodeInnerHtml(findTreeNode(state.tree.result.root, guid), state.tree.result);
      b.innerHTML = "&#9662;";
      bindTreeNodes(bodyEl);
    }
  }));
  scope.querySelectorAll(".pt-head [data-filter]").forEach((b) => b.addEventListener("click", (e) => {
    e.stopPropagation();
    state.log.keyword = b.dataset.filter;
    $("#fltKeyword").value = state.log.keyword;
    state.log.page = 1;
    $("#treeModal").classList.add("hidden");
    loadEvents();
    toast("已按进程 GUID 筛选日志");
  }));
}

/* ===================== P2: 事件表格层级分组 ===================== */

const MAX_GROUP_ROWS = 50;

function onGroupDimChange() {
  const dims = [];
  $$("#grpMenu .grp-opt input").forEach((c) => { if (c.checked) dims.push(c.value); });
  state.log.groupDims = dims;
  const names = { process: "进程", type: "事件类型", user: "用户" };
  $("#btnGroup").innerHTML = "&#9638; 分组: " + (dims.length ? dims.map((d) => names[d]).join("+") : "无") + " &#9662;";
  state.log.page = 1;
  loadEvents();
}

function grpKeyMeta(ev, dim) {
  const d = dataMap(ev);
  if (dim === "process") {
    const v = d.Image || d.SourceImage || d.ImageLoaded || "";
    if (!v) return { key: "?", label: "（未知进程）", title: "事件中无进程字段", filterKind: "", filterVal: "" };
    return { key: v, label: baseName(v), title: v, filterKind: "keyword", filterVal: v };
  }
  if (dim === "type") {
    const name = state.meta.eid_names[ev.event_id] || "未知事件";
    return { key: String(ev.event_id), label: `EID ${ev.event_id} ${name}`, title: name, filterKind: "eid", filterVal: String(ev.event_id) };
  }
  const v = d.User || d.SourceUser || d.TargetUser || "";
  if (!v) return { key: "?", label: "（未知用户）", title: "事件中无用户字段", filterKind: "", filterVal: "" };
  return { key: v, label: v, title: v, filterKind: "keyword", filterVal: v };
}

function buildGroups(idxs, dims, prefix) {
  const dim = dims[0];
  const map = new Map();
  for (const gi of idxs) {
    const meta = grpKeyMeta(state.log.data[gi], dim);
    if (!map.has(meta.key)) {
      map.set(meta.key, { ...meta, path: prefix + "\u0001" + meta.key, count: 0, rows: [], groups: [] });
    }
    const g = map.get(meta.key);
    g.count++;
    g.rows.push(gi);
  }
  const groups = [...map.values()].sort((a, b) => b.count - a.count);
  if (dims.length > 1) {
    for (const g of groups) {
      g.groups = buildGroups(g.rows, dims.slice(1), g.path);
      g.rows = [];
    }
  }
  return groups;
}

function countGroups(groups) {
  let n = 0;
  for (const g of groups) {
    n++;
    if (g.groups.length) n += countGroups(g.groups);
  }
  return n;
}

function findGroupByPath(groups, path) {
  for (const g of groups || []) {
    if (g.path === path) return g;
    const sub = findGroupByPath(g.groups, path);
    if (sub) return sub;
  }
  return null;
}

function groupRowHtml(g, level) {
  const open = state.log.openGroups.has(g.path);
  const hasSub = g.groups.length > 0;
  let inner = "";
  if (open) {
    if (hasSub) {
      inner = g.groups.map((c) => groupRowHtml(c, level + 1)).join("");
    } else {
      inner = g.rows.slice(0, MAX_GROUP_ROWS).map((i) => eventRowHtml(state.log.data[i], i, false)).join("");
      const shown = Math.min(g.rows.length, MAX_GROUP_ROWS);
      if (g.count > shown) {
        inner += `<tr class="grp-more"><td colspan="4">… 本组共 ${g.count} 条，仅展开前 ${shown} 条，点击组行 &#128269; 下钻查看全部</td></tr>`;
      }
    }
  }
  const caret = hasSub || g.rows.length ? (open ? "&#9662;" : "&#9656;") : "";
  const filterBtn = g.filterKind ? `<button class="btn sm act-btn" data-gfilter="${esc(g.path)}" title="按此组快速筛选明细">&#128269;</button>` : "";
  return `<tr class="grp-row" data-gpath="${esc(g.path)}"><td colspan="4" style="padding-left:${14 + level * 22}px">
      <span class="grp-caret">${caret}</span> <span class="grp-label" title="${esc(g.title || g.label)}">${esc(g.label)}</span>
      <span class="badge b-gray">${g.count} 条</span> ${filterBtn}
    </td></tr>${inner}`;
}

function bindGroupRows(scope) {
  scope.querySelectorAll("tr.grp-row[data-gpath]").forEach((tr) => {
    tr.addEventListener("click", (e) => {
      if (e.target.closest("[data-gfilter]")) return;
      const path = tr.dataset.gpath;
      if (state.log.openGroups.has(path)) state.log.openGroups.delete(path);
      else state.log.openGroups.add(path);
      renderGroupedEvents();
    });
    const fb = tr.querySelector("[data-gfilter]");
    if (fb) fb.addEventListener("click", (e) => {
      e.stopPropagation();
      const g = findGroupByPath(state.log._groups, fb.dataset.gfilter);
      if (!g) return;
      if (g.filterKind === "eid") {
        state.log.eventId = g.filterVal;
        $("#fltEvent").value = g.filterVal;
      } else {
        state.log.keyword = g.filterVal;
        $("#fltKeyword").value = g.filterVal;
      }
      state.log.page = 1;
      loadEvents();
      toast("已按「" + g.label + "」筛选（分组保持生效）");
    });
  });
}

function renderGroupedEvents() {
  const data = state.log.data;
  if (!data.length) {
    $("#evtBody").innerHTML = '<tr><td colspan="4" class="empty">无匹配事件</td></tr>';
    $("#evtPager").innerHTML = "";
    return;
  }
  const groups = buildGroups(data.map((_, i) => i), state.log.groupDims, "");
  state.log._groups = groups;
  $("#evtBody").innerHTML = groups.map((g) => groupRowHtml(g, 0)).join("");
  bindGroupRows($("#evtBody"));
  bindEventRows($("#evtBody"));
  $("#evtPager").innerHTML = `<span>分组视图：共 ${data.length} 条事件 · ${countGroups(groups)} 个分组（当前窗口全量，不分页）</span>`;
}

/* ===================== P3a: GeoIP 归属地 ===================== */

function toggleGeoIP() {
  state.geo.enabled = $("#chkGeoIP").checked;
  try { localStorage.setItem("sysmonGeoIP", state.geo.enabled ? "1" : "0"); } catch (e) { }
  if (state.geo.enabled) {
    toast(state.geo.mmdb && state.geo.mmdb.mmdb_loaded
      ? `已启用 GeoIP：离线库 ${state.geo.mmdb.mmdb_type} 解析（不外发 IP）`
      : "已启用 GeoIP：未发现离线库，外联 IP 将批量提交至 ip-api.com（本地缓存 30 天）");
    loadGeoStatus();
  }
  $("#geoPanel").classList.toggle("hidden", !state.geo.enabled);
  if (state.log.data.length) {
    if (state.log.grouped) renderGroupedEvents(); else renderEvents();
    renderGeoPanel();
  }
}

async function loadGeoStatus() {
  try {
    state.geo.mmdb = await api("/api/geoip/status");
    if (state.geo.enabled) renderGeoPanel();
  } catch (e) { /* 忽略，面板显示默认提示 */ }
}

async function geoLookup(ips) {
  const uniq = [...new Set(ips.filter(Boolean))];
  const need = uniq.filter((ip) => !(ip in state.geo.cache));
  if (need.length) {
    try {
      const d = await api("/api/geoip", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ips: need }) });
      for (const ip of need) {
        const info = d[ip];
        state.geo.cache[ip] = info && info.country ? info : null;
      }
    } catch (e) {
      const now = Date.now();
      if (now - state.geo.lastErr > 10000) {
        state.geo.lastErr = now;
        toast("GeoIP 查询失败: " + e.message, "err");
      }
      for (const ip of need) if (!(ip in state.geo.cache)) state.geo.cache[ip] = null;
    }
  }
  return state.geo.cache;
}

function fillGeoBadges(scope) {
  if (!state.geo.enabled) return;
  const spans = Array.from(scope.querySelectorAll("[data-geoip]"));
  if (!spans.length) return;
  geoLookup(spans.map((s) => s.dataset.geoip)).then((cache) => {
    spans.forEach((s) => {
      const info = cache[s.dataset.geoip];
      if (info && info.country) {
        s.textContent = info.country;
        s.title = info.code && info.code.length === 2 ? info.code.toUpperCase() : (info.code || "");
        s.classList.add(["priv", "loopback", "linklocal", "multicast", "unspecified"].includes(info.code) ? "local" : "on");
      } else {
        s.textContent = "—";
        s.title = "未解析";
        s.classList.add("miss");
      }
    });
  });
}

function renderGeoPanel() {
  const panel = $("#geoPanel");
  if (!state.geo.enabled) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  const mmdbOn = state.geo.mmdb && state.geo.mmdb.mmdb_loaded;
  const mmdbBadge = state.geo.mmdb
    ? (mmdbOn
      ? `<span class="badge b-green" title="离线 MaxMind 库解析，不外发 IP">离线: ${esc(state.geo.mmdb.mmdb_type || "mmdb")}</span>`
      : `<span class="badge b-orange" title="${esc(state.geo.mmdb.hint || "")}">在线 ip-api（放入 GeoLite2-City.mmdb 可离线）</span>`)
    : "";
  const ipCount = new Map();
  for (const ev of state.log.data) {
    if (ev.event_id !== 3) continue;
    const ip = dataMap(ev).DestinationIp;
    if (ip && IP_LIKE.test(ip)) ipCount.set(ip, (ipCount.get(ip) || 0) + 1);
  }
  if (!ipCount.size) {
    panel.innerHTML = `<span class="hint">当前已加载事件中无网络连接 (EID 3) 目标 IP，暂无外联统计</span> ${mmdbBadge}`;
    return;
  }
  panel.innerHTML = `<span class="hint">外联国家统计中…（${ipCount.size} 个目标 IP）</span> ${mmdbBadge}`;
  geoLookup([...ipCount.keys()]).then((cache) => {
    const byCountry = new Map();
    for (const [ip, n] of ipCount) {
      const info = cache[ip];
      const key = info && info.country ? info.country : "未解析";
      const cur = byCountry.get(key) || { count: 0, ips: new Set(), code: "", lat: null, lon: null };
      cur.count += n;
      cur.ips.add(ip);
      if (info) {
        if (!cur.code && info.code && info.code.length === 2) cur.code = info.code;
        if (cur.lat == null && info.lat != null) { cur.lat = info.lat; cur.lon = info.lon; }
      }
      byCountry.set(key, cur);
    }
    state.geo.lastStats = byCountry;
    const top = [...byCountry.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 10);
    const max = top.length ? top[0][1].count : 1;
    panel.innerHTML = `
      <div class="geo-title">外联国家 TOP${top.length}
        <span class="hint">（当前已加载 ${state.log.data.length} 条事件 / ${ipCount.size} 个目标 IP）</span>
        ${mmdbBadge}
        <button class="btn sm" id="btnGeoMap" title="在世界地图上查看外联分布">&#127758; 地图</button>
      </div>
      <div class="geo-bars">
        ${top.map(([c, v]) => `
        <div class="geo-bar-row" title="${esc(c)}：${v.count} 次连接 / ${v.ips.size} 个 IP">
          <span class="geo-bar-label">${esc(c)}</span>
          <span class="geo-bar"><span class="geo-bar-fill" style="width:${Math.max(4, Math.round((v.count / max) * 100))}%"></span></span>
          <span class="geo-bar-num">${v.count}</span>
        </div>`).join("")}
      </div>`;
    const mb = $("#btnGeoMap");
    if (mb) mb.addEventListener("click", openGeoMap);
  });
}

/* ===================== P3b: 外联世界地图 ===================== */

const A2_A3 = (() => {
  const s = "AD:AND,AE:ARE,AF:AFG,AG:ATG,AI:AIA,AL:ALB,AM:ARM,AO:AGO,AQ:ATA,AR:ARG,AS:ASM,AT:AUT,AU:AUS,AW:ABW,AX:ALA,AZ:AZE,BA:BIH,BB:BRB,BD:BGD,BE:BEL,BF:BFA,BG:BGR,BH:BHR,BI:BDI,BJ:BEN,BL:BLM,BM:BMU,BN:BRN,BO:BOL,BQ:BES,BR:BRA,BS:BHS,BT:BTN,BV:BVT,BW:BWA,BY:BLR,BZ:BLZ,CA:CAN,CC:CCK,CD:COD,CF:CAF,CG:COG,CH:CHE,CI:CIV,CK:COK,CL:CHL,CM:CMR,CN:CHN,CO:COL,CR:CRI,CU:CUB,CV:CPV,CW:CUW,CX:CXR,CY:CYP,CZ:CZE,DE:DEU,DJ:DJI,DK:DNK,DM:DMA,DO:DOM,DZ:DZA,EC:ECU,EE:EST,EG:EGY,EH:ESH,ER:ERI,ES:ESP,ET:ETH,FI:FIN,FJ:FJI,FK:FLK,FM:FSM,FO:FRO,FR:FRA,GA:GAB,GB:GBR,GD:GRD,GE:GEO,GF:GUF,GG:GGY,GH:GHA,GI:GIB,GL:GRL,GM:GMB,GN:GIN,GP:GLP,GQ:GNQ,GR:GRC,GS:SGS,GT:GTM,GU:GUM,GW:GNB,GY:GUY,HK:HKG,HM:HMD,HN:HND,HR:HRV,HT:HTI,HU:HUN,ID:IDN,IE:IRL,IL:ISR,IM:IMN,IN:IND,IO:IOT,IQ:IRQ,IR:IRN,IS:ISL,IT:ITA,JE:JEY,JM:JAM,JO:JOR,JP:JPN,KE:KEN,KG:KGZ,KH:KHM,KI:KIR,KM:COM,KN:KNA,KP:PRK,KR:KOR,KW:KWT,KY:CYM,KZ:KAZ,LA:LAO,LB:LBN,LC:LCA,LI:LIE,LK:LKA,LR:LBR,LS:LSO,LT:LTU,LU:LUX,LV:LVA,LY:LBY,MA:MAR,MC:MCO,MD:MDA,ME:MNE,MF:MAF,MG:MDG,MH:MHL,MK:MKD,ML:MLI,MM:MMR,MN:MNG,MO:MAC,MP:MNP,MQ:MTQ,MR:MRT,MS:MSR,MT:MLT,MU:MUS,MV:MDV,MW:MWI,MX:MEX,MY:MYS,MZ:MOZ,NA:NAM,NC:NCL,NE:NER,NF:NFK,NG:NGA,NI:NIC,NL:NLD,NO:NOR,NP:NPR,NR:NRU,NU:NIU,NZ:NZL,OM:OMN,PA:PAN,PE:PER,PF:PYF,PG:PNG,PH:PHL,PK:PAK,PL:POL,PM:SPM,PN:PCN,PR:PRI,PS:PSE,PT:PRT,PW:PLW,PY:PRY,QA:QAT,RE:REU,RO:ROU,RS:SRB,RU:RUS,RW:RWA,SA:SAU,SB:SLB,SC:SYC,SD:SDN,SE:SWE,SG:SGP,SH:SHN,SI:SVN,SJ:SJM,SK:SVK,SL:SLE,SM:SMR,SN:SEN,SO:SOM,SR:SUR,SS:SSD,ST:STP,SV:SLV,SX:SXM,SY:SYR,SZ:SWZ,TC:TCA,TD:TCD,TF:ATF,TG:TGO,TH:THA,TJ:TJK,TK:TKL,TL:TLS,TM:TKM,TN:TUN,TO:TON,TR:TUR,TT:TTO,TV:TUV,TW:TWN,TZ:TZA,UA:UKR,UG:UGA,UM:UMI,US:USA,UY:URY,UZ:UZB,VA:VAT,VC:VCT,VE:VEN,VG:VGB,VI:VIR,VN:VNM,VU:VUT,WF:WLF,WS:WSM,YE:YEM,YT:MYT,ZA:ZAF,ZM:ZMB,ZW:ZWE";
  const m = {};
  for (const pair of s.split(",")) { const [a, b] = pair.split(":"); m[a] = b; }
  return m;
})();

let worldGeo = null;

async function openGeoMap() {
  if (!state.geo.lastStats || !state.geo.lastStats.size) {
    toast("暂无外联统计数据（需先加载含网络连接的事件）", "err");
    return;
  }
  if (!worldGeo) {
    try {
      const r = await fetch("/countries.geojson");
      if (!r.ok) throw new Error("HTTP " + r.status);
      worldGeo = await r.json();
    } catch (e) {
      toast("加载世界地图数据失败: " + e.message, "err");
      return;
    }
  }
  renderGeoMap();
}

function renderGeoMap() {
  const W = 960, H = 480;
  const stats = state.geo.lastStats;
  const byA3 = new Map();
  let max = 1;
  for (const [name, v] of stats) {
    if (!v.code) continue;
    const a3 = A2_A3[v.code.toUpperCase()];
    if (!a3) continue;
    byA3.set(a3, name);
    if (v.count > max) max = v.count;
  }
  const proj = (lon, lat) => [((lon + 180) / 360) * W, ((90 - lat) / 180) * H];
  const shade = (c) => {
    const t = Math.sqrt(c / max);
    const from = [219, 234, 254], to = [30, 64, 175];
    const mix = from.map((f, i) => Math.round(f + (to[i] - f) * t));
    return `rgb(${mix.join(",")})`;
  };
  let paths = "";
  for (const f of worldGeo.features) {
    const a3 = f.id;
    if (!a3) continue;
    const g = f.geometry;
    if (!g) continue;
    const polys = g.type === "Polygon" ? [g.coordinates] : g.type === "MultiPolygon" ? g.coordinates : [];
    let d = "";
    for (const poly of polys) {
      for (const ring of poly) {
        for (let i = 0; i < ring.length; i++) {
          const [x, y] = proj(ring[i][0], ring[i][1]);
          d += (i === 0 ? "M" : "L") + x.toFixed(1) + "," + y.toFixed(1);
        }
        d += "Z";
      }
    }
    const cn = byA3.get(a3);
    const cnt = cn ? stats.get(cn).count : 0;
    paths += `<path d="${d}" fill="${cn ? shade(cnt) : "var(--map-empty)"}" stroke="var(--map-stroke)" stroke-width="0.5">${cn ? `<title>${esc(cn)}: ${cnt} 次连接 / ${stats.get(cn).ips.size} 个 IP</title>` : ""}</path>`;
  }
  let dots = "";
  for (const [name, v] of stats) {
    if (v.lat == null || v.lon == null) continue;
    const [x, y] = proj(v.lon, v.lat);
    const r = 3 + Math.sqrt(v.count) * 1.2;
    dots += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r.toFixed(1)}" fill="rgba(220,38,38,.75)" stroke="#fff" stroke-width="1"><title>${esc(name)}: ${v.count} 次连接</title></circle>`;
  }
  $("#mapModalTitle").textContent = `外联地图（${stats.size} 个国家/地区）`;
  $("#mapBody").innerHTML = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto;background:var(--map-bg);border-radius:8px">${paths}${dots}</svg>`;
  $("#mapHint").textContent = dots
    ? "颜色深浅 = 该国外联次数；红点 = City 离线库提供的坐标（点大小 = 频次）"
    : "颜色深浅 = 该国外联次数（使用 GeoLite2-City.mmdb 可显示坐标圆点）";
  $("#mapModal").classList.remove("hidden");
}

/* ===================== 筛选预设 ===================== */

function loadFilterPresets() {
  try { return JSON.parse(localStorage.getItem("sysmonFilters") || "[]"); } catch (e) { return []; }
}

function saveFilterPresets(list) {
  try { localStorage.setItem("sysmonFilters", JSON.stringify(list)); } catch (e) { }
}

function renderFilterPresets() {
  const list = loadFilterPresets();
  const box = $("#filterPresets");
  if (!list.length) { box.innerHTML = ""; return; }
  box.innerHTML = '<span class="pb-title">已存筛选:</span>' + list.map((p, i) => `
    <span class="preset-chip" data-preset="${i}" title="EID ${esc(p.eventId || "全部")}${p.keyword ? " · " + esc(p.keyword) : ""}${p.hours ? " · " + p.hours + "h" : ""} · " + p.fetch + "条">${esc(p.name)}
      <button data-preset-del="${i}" title="删除预设">&times;</button></span>`).join("");
  box.querySelectorAll("[data-preset]").forEach((c) => c.addEventListener("click", (e) => {
    if (e.target.closest("[data-preset-del]")) return;
    const p = loadFilterPresets()[+c.dataset.preset];
    if (!p) return;
    state.log.eventId = p.eventId || "";
    state.log.keyword = p.keyword || "";
    state.log.hours = p.hours || "";
    state.log.fetch = +p.fetch || 1000;
    $("#fltEvent").value = state.log.eventId;
    $("#fltKeyword").value = state.log.keyword;
    $("#fltHours").value = state.log.hours;
    $("#fltFetch").value = String(state.log.fetch);
    state.log.page = 1;
    loadEvents();
    toast("已应用筛选预设「" + p.name + "」");
  }));
  box.querySelectorAll("[data-preset-del]").forEach((b) => b.addEventListener("click", (e) => {
    e.stopPropagation();
    const list2 = loadFilterPresets();
    list2.splice(+b.dataset.presetDel, 1);
    saveFilterPresets(list2);
    renderFilterPresets();
  }));
}

function saveFilterPreset() {
  const defName = (state.log.eventId ? "EID" + state.log.eventId + " " : "") + (state.log.keyword.trim() ? state.log.keyword.trim().slice(0, 12) : "全部");
  const name = window.prompt("预设名称:", defName);
  if (name === null) return;
  const n = name.trim();
  if (!n) { toast("名称不能为空", "err"); return; }
  const list = loadFilterPresets();
  if (list.length >= 12) { toast("最多保存 12 个预设，请先删除旧的", "err"); return; }
  list.push({ name: n, eventId: state.log.eventId, keyword: state.log.keyword.trim(), hours: state.log.hours, fetch: state.log.fetch });
  saveFilterPresets(list);
  renderFilterPresets();
  toast("筛选预设已保存");
}

/* ===================== 检测剧本快捷筛选 ===================== */

const PLAYBOOKS = [
  { name: "凭证访问 lsass", eid: 10, kw: "lsass", tip: "EID10 ProcessAccess 目标为 lsass.exe（关注 0x1010 等读取权限）" },
  { name: "Office 派生进程", eid: 1, kw: "winword.exe|excel.exe|powerpnt.exe|msaccess.exe|onenote.exe|outlook.exe", tip: "EID1 父进程为 Office 套件（典型鱼叉/宏 payload 落地链）" },
  { name: "脚本解释器启动", eid: 1, kw: "powershell|wscript|cscript|mshta", tip: "EID1 命令行/镜像含脚本解释器（关注 -enc/URLDownloadToFile）" },
  { name: "系统下载器", eid: 1, kw: "certutil|bitsadmin|mshta", tip: "EID1 命令行含系统自带下载工具（Living-off-the-Land）" },
  { name: "临时目录执行", eid: 1, kw: "\\Temp\\|\\AppData\\", tip: "EID1 镜像/命令行位于 Temp 或 AppData（用户态落地常见路径）" },
  { name: "未签名驱动", eid: 6, kw: "", tip: "EID6 驱动加载全部事件（摘要列可见「未签名」标记）" },
  { name: "DNS 查询", eid: 22, kw: "", tip: "EID22 DNS 查询全部事件" },
  { name: "网络外联", eid: 3, kw: "", tip: "EID3 网络连接全部事件（可配合 GeoIP 面板）" },
];

function renderPlaybooks() {
  $("#playbookBar").innerHTML =
    '<span class="pb-title" title="一键应用常见调查场景的 EID + 关键字组合（关键字支持 | 分隔任一命中）">检测剧本:</span>' +
    PLAYBOOKS.map((pb, i) => `<button class="pb-chip" data-pb="${i}" title="${esc(pb.tip)}&#10;EID ${pb.eid}${pb.kw ? " · 关键字: " + esc(pb.kw) : ""}">${esc(pb.name)}</button>`).join("");
  $("#playbookBar").querySelectorAll("[data-pb]").forEach((b) => b.addEventListener("click", () => {
    const pb = PLAYBOOKS[+b.dataset.pb];
    state.log.eventId = String(pb.eid);
    state.log.keyword = pb.kw;
    $("#fltEvent").value = state.log.eventId;
    $("#fltKeyword").value = state.log.keyword;
    state.log.page = 1;
    $$("#playbookBar .pb-chip").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    loadEvents();
    toast(`已应用剧本「${pb.name}」(EID ${pb.eid})`);
  }));
  // 手动修改筛选时清除剧本高亮
  $("#fltKeyword").addEventListener("input", () => $$("#playbookBar .pb-chip").forEach((x) => x.classList.remove("active")));
  $("#fltEvent").addEventListener("change", () => $$("#playbookBar .pb-chip").forEach((x) => x.classList.remove("active")));
}

/* ===================== 规则试算 (dry-run) ===================== */

function condMatchSim(cond, ev) {
  const dm = dataMap(ev);
  let field = null;
  for (const k of Object.keys(dm)) {
    if (k.toLowerCase() === String(cond.field || "").toLowerCase()) { field = k; break; }
  }
  if (!field) return false;
  const val = (dm[field] || "").toLowerCase();
  const vals = (cond.values || []).map((v) => String(v).toLowerCase());
  if (!vals.length) return false;
  const num = (s) => { const n = parseFloat(s); return isNaN(n) ? null : n; };
  switch (cond.op) {
    case "is": return vals.some((v) => val === v);
    case "is not": return !vals.some((v) => val === v);
    case "contains":
    case "contains any": return vals.some((v) => val.includes(v));
    case "contains all": return vals.every((v) => val.includes(v));
    case "excludes":
    case "excludes any": return !vals.some((v) => val.includes(v));
    case "excludes all": return !vals.every((v) => val.includes(v));
    case "begin with": return vals.some((v) => val.startsWith(v));
    case "not begin with": return !vals.some((v) => val.startsWith(v));
    case "end with": return vals.some((v) => val.endsWith(v));
    case "not end with": return !vals.some((v) => val.endsWith(v));
    case "image": {
      const parts = val.split("\\").filter(Boolean);
      return vals.some((v) => val === v || parts.includes(v));
    }
    case "lower than": return vals.some((v) => { const a = num(val), b = num(v); return a !== null && b !== null && a < b; });
    case "higher than": return vals.some((v) => { const a = num(val), b = num(v); return a !== null && b !== null && a > b; });
    default: return false;
  }
}

function ruleMatchesSim(rule, ev, targetEid) {
  if (targetEid && ev.event_id !== targetEid) return false;
  return (rule.groups || []).some((g) => {
    const rel = g.relation === "or"
      ? g.conditions.some((c) => condMatchSim(c, ev))
      : g.conditions.every((c) => condMatchSim(c, ev));
    return rel;
  });
}

function simulateRule() {
  const r = state.editing;
  if (!r) return;
  const conds = (r.groups || []).reduce((n, g) => n + (g.conditions || []).filter((c) => c.field && (c.values || []).length).length, 0);
  if (!conds) { toast("规则至少需要一个完整条件才能试算", "err"); return; }
  const t = state.meta.event_types.find((x) => x.type === r.event_type);
  const eid = t ? t.event_id : 0;
  const data = state.log.data;
  const typed = eid ? data.filter((ev) => ev.event_id === eid) : [];
  const hits = typed.filter((ev) => ruleMatchesSim(r, ev, eid));
  const isExclude = r.on_match === "exclude";
  const effect = isExclude
    ? `若部署：这 ${hits.length} 条将被<b style="color:var(--danger)">排除</b>（不记录日志）`
    : `若部署：这 ${hits.length} 条将被<b style="color:var(--success)">记录</b>`;
  $("#simModalTitle").textContent = `规则试算 — ${r.name || "（未命名规则）"}`;
  const show = hits.slice(0, 50);
  $("#simBody").innerHTML = `
    <div class="import-stats">
      <span class="badge b-blue">${t ? esc(t.label) + " (EID " + eid + ")" : "未知类型"}</span>
      <span class="badge b-gray">窗口事件 ${data.length} 条</span>
      <span class="badge b-gray">同类型 ${typed.length} 条</span>
      <span class="badge ${hits.length ? "b-orange" : "b-green"}">命中 ${hits.length} 条</span>
    </div>
    <div class="hint" style="margin:8px 0">${effect}${hits.length ? "，命中示例：" : ""}</div>
    ${hits.length ? `<div class="sim-list">${show.map((ev) => `
      <div class="sim-row">
        <span class="pt-ev-time">${esc(fmtTime(ev.time))}</span>
        <span class="eid-badge ${eidClsName(ev.event_id)}">${ev.event_id}</span>
        <span class="pt-ev-sum">${eventSummary(ev)}</span>
      </div>`).join("")}${hits.length > show.length ? `<div class="sim-row more">… 共 ${hits.length} 条命中，仅显示前 ${show.length} 条</div>` : ""}</div>` :
      '<div class="empty" style="text-align:center;color:var(--muted);padding:26px">当前窗口内无命中事件' + (typed.length ? "" : "（窗口内没有该类型的事件，可尝试增大「加载条数」或放宽筛选）") + "</div>"}`;
  $("#simModal").classList.remove("hidden");
}

/* ===================== 配置差异（已部署 vs 当前） ===================== */

async function showRulesDiff() {
  let dep;
  try {
    dep = await api("/api/rules/deployed");
  } catch (e) { toast(e.message, "err"); return; }
  if (!dep.available) { showResult("配置差异", "暂无部署快照（旧版本部署的配置未留存快照）。\n下次点击「应用规则到 Sysmon」成功后即可对比差异。"); return; }
  const cur = state.rules.rules || [];
  const old = (dep.rules && dep.rules.rules) || [];
  const byId = (list) => { const m = new Map(); for (const r of list) m.set(r.id || r.name, r); return m; };
  const curMap = byId(cur), oldMap = byId(old);
  const added = cur.filter((r) => !oldMap.has(r.id || r.name));
  const removed = old.filter((r) => !curMap.has(r.id || r.name));
  const changed = cur.filter((r) => {
    const o = oldMap.get(r.id || r.name);
    return o && JSON.stringify(o) !== JSON.stringify(r);
  });
  const fmtRule = (r) => `  · [${r.enabled ? "启用" : "停用"}][${r.on_match === "include" ? "记录" : "排除"}] ${r.name} (条件 ${(r.groups || []).reduce((n, g) => n + (g.conditions || []).length, 0)} 个)`;
  let text = `当前 ${cur.length} 条 / 已部署 ${old.length} 条\n`;
  if (!added.length && !removed.length && !changed.length) {
    text += "\n规则内容一致（差异仅可能在全局选项或顺序）。";
  } else {
    if (added.length) { text += `\n新增 (${added.length}):\n` + added.map(fmtRule).join("\n"); }
    if (removed.length) { text += `\n删除 (${removed.length}):\n` + removed.map(fmtRule).join("\n"); }
    if (changed.length) {
      text += `\n修改 (${changed.length}):\n`;
      for (const r of changed) {
        const o = oldMap.get(r.id || r.name);
        text += `  · ${r.name}\n    旧: ${fmtRule(o).trim().slice(2)}\n    新: ${fmtRule(r).trim().slice(2)}\n`;
      }
    }
  }
  showResult("配置差异 — 已部署 vs 当前未部署", text);
}

/* ===================== 运行日志页 ===================== */

async function loadAppLog(silent) {
  try {
    const r = await fetch("/api/applog");
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const text = await r.text();
    $("#applogPre").textContent = text || "（日志为空）";
    if (!silent) $("#applogPre").scrollTop = $("#applogPre").scrollHeight;
  } catch (e) {
    $("#applogPre").textContent = "加载失败: " + e.message;
  }
}

init().catch((e) => toast("初始化失败: " + e.message, "err"));