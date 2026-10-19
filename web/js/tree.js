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
