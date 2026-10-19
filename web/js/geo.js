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
