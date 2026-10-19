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


async function deploy() {
  if (!(await saveRulesToServer())) return;
  toast("规则已保存，正在部署…");
  switchTab("status");
  await sysmonOp("install");
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
