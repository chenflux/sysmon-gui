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


function showResult(title, text) {
  $("#resultModalTitle").textContent = title;
  $("#resultPre").textContent = text;
  $("#resultModal").classList.remove("hidden");
}


/* ===================== EID 彩色徽标 ===================== */

const EID_CLS = { 1: "proc", 5: "proc", 25: "proc", 3: "net", 22: "dns", 2: "file", 11: "file", 15: "file", 23: "file", 26: "file", 27: "file", 28: "file", 29: "file", 12: "reg", 13: "reg", 14: "reg", 8: "inj", 10: "inj", 9: "inj", 17: "pipe", 18: "pipe", 6: "drv", 7: "img", 19: "wmi", 20: "wmi", 21: "wmi" };
function eidClsName(id) { return "eid-" + (EID_CLS[id] || "oth"); }
