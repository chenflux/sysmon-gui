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