function renderEventFilter() {
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
