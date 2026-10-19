# Sysmon GUI 功能路线图（分析增强篇）

> 依据 nshalabi/SysmonTools (GPLv3) 的交互思路整理。**仅借鉴设计思想，不复制其代码与资源文件**（GPL 许可证不兼容）。
> 现状基线：日志查看页已支持 EID/关键字/时间筛选、事件详情展开、按字段快速下钻（🔍）、哈希/IP/域名 VirusTotal 跳转。
>
> **实施进度（2026-10）**：P1 / P2 / P3a / P4 / P5 已全部落地 ✅（P3b 地图已实现，坐标打点需 City 离线库）。

## P1 - 进程谱系树与行为时间线 ✅ 已实现（建议下一步实施）

### 目标效果
在事件详情中一键查看某进程的完整行为链：

```
▼ winword.exe  (PID 4012, GUID aabb...)
  │  启动于 10-18 14:22:03
  ├─ 创建 powershell.exe -enc JAB...        [EID1]
  │   ├─ 写入 bad.ps1                        [EID11]
  │   ├─ 访问 lsass.exe (0x1010)             [EID10]
  │   └─ 连接 45.33.x.x:443                  [EID3]
  └─ 创建 cmd.exe /c certutil ...            [EID1]
```

### 回答的调查问题
"该进程从哪来（父进程链）、干了什么（全部关联事件）、产生了什么后果（子进程链）"。
目前需要分析师手动按 ProcessGuid/Image 反复筛选拼凑，此功能把故事线直接画出来。

### 技术方案（结合现有架构）
- 数据源：EID 1 的 `ProcessGuid / ParentProcessGuid / ProcessId / ParentProcessId / Image / CommandLine` 自关联成树；
  其余事件（3/7/10/11/22 等）按 `ProcessGuid` 挂到对应节点的时间线上
- 后端：新增 `GET /api/events/process-tree?guid=<ProcessGuid>&fetch=5000`
  复用 `internal/events.Query` 拉取窗口，在 Go 侧建树返回 JSON（节点 + 子事件列表 + 祖先链）
- 前端：纯 HTML/CSS 可折叠嵌套列表（无需图形库），节点带事件类型彩色徽标；
  详情面板中 ProcessGuid/ProcessId 旁增加「🌳 查看进程谱系」按钮
- 已知限制（需在 UI 中说明）：受"加载条数上限 5000"约束，窗口外启动的进程显示为根节点（父链缺失）

### 工作量与验收
- 工作量：约 2-4 天（后端建树 0.5 天 + 前端树组件 1-2 天 + 打磨）
- 验收：对任一 EID1 事件点开谱系，能看到祖先链、全部子进程、每进程聚合事件；树可折叠/展开
- **✅ 验收通过**：实现见 `internal/events/proctree.go`（建树，含单元测试）、`GET /api/events/process-tree`、
  前端树形弹窗（详情面板 ProcessGuid/ProcessId/Source·TargetProcessGuid 旁 🌳 按钮）。
  祖先链自动剪枝（仅保留通向焦点进程的分支）、窗口外进程标记「窗口外」、单节点事件超 200 条截断提示、
  全部展开/折叠、节点 🔍 按 GUID 下钻。

## P2 - 事件表格层级分组（数据透视）✅ 已实现

### 目标效果
按"进程 / 事件类型 / 用户 / 计算机"等维度对已加载事件做层级折叠汇总：

```
▼ chrome.exe (1,247 条)
   ▼ 网络连接 (832)   ▼ 镜像加载 (415)
▼ svchost.exe (3,120 条)
```

### 回答的调查问题
"谁在制造日志洪水 / 哪个进程异常活跃"——快速定位噪音大户，也可作为 P1 树视图的平替概览。

### 技术方案
- 纯前端改造：在当前 fetch 窗口（内存数据）上分组，不新增后端接口
- 第一版用「分组维度下拉多选」（进程/事件类型/用户），拖拽列头交互后置
- 组行可点击展开为普通表格行；组行提供 🔍 快速筛选（下钻到该组的明细视图）

### 工作量与验收
- 工作量：1-2 天
- 验收：选择分组维度后正确折叠计数、展开明细、组行可一键筛选
- **✅ 验收通过**：纯前端实现（`web/app.js` 分组模块），维度多选（进程/事件类型/用户，按序层级嵌套），
  分组视图一次性拉取全窗口（后端 page_size 上限提升至 5000，同时修复 CSV 导出仅 200 条的缺陷），
  组行计数排序折叠、叶组展开前 50 条明细、组行 🔍 一键下钻（事件类型走 EID 精确筛选，其余走关键字）、
  展开状态在自动刷新间保持。

## P3 - GeoIP 外联地图（高成本，先做廉价版）

### 目标效果
EID3 网络连接的目的 IP 落到世界地图上（点大小=频次），地域异常（如罕见国家密集连线）一眼可见。

### 回答的调查问题
"这台机器在和世界上哪些地方通信？"

### 分阶段方案
- **P3a 廉价版（建议先做）**：详情行/汇总面板加「IP → 国家」文本列（离线 GeoLite2-Country 库或按需在线批量查询 + 本地缓存），
  并提供「外联国家 TOP10」统计条；无地图
- **P3b 完整版（后置）**：离线世界地图（自备 geojson + SVG 渲染，勿用 SysmonTools 资源）+ 离线 mmdb 解析
- 依赖与风险：MaxMind GeoLite2 需注册并每月更新（~6MB）；在线 API（ip-api 等）有速率限制且外泄 IP 清单，默认应关闭

### 工作量
- P3a：1-2 天；P3b：+3-5 天（含离线资源打包与更新机制）
- **✅ P3a 验收通过**：`internal/geoip`（ip-api.com 批量查询 100/批 + `geoip-cache.json` 本地缓存 30 天 +
  私网/回环/链路本地 IP 本地判定不外发，含单元测试）、`POST /api/geoip`（单次上限 1000 IP）。
  前端 GeoIP 开关默认关闭（localStorage 记忆，含隐私提示），详情 DestinationIp/SourceIp 行显示国家徽标，
  日志页顶部「外联国家 TOP10」条形统计。

## 明确暂缓（来自 SysmonTools 但不建议跟进）

| 功能 | 原因 |
|---|---|
| 自由拖拽画布 / 节点钉住 | 重交互、维护成本高，折叠树已覆盖 90% 场景 |
| VirusTotal API 深度集成 | 需 API Key 与配额管理，外链跳转已够用 |
| 跨平台 (macOS/Linux) | 依赖 Windows 事件日志与 Sysmon，无意义 |

## 实施顺序建议

1. **P1 进程谱系树** —— 价值最高，与既有 🔍 下钻天然衔接
2. **P2 分组汇总** —— 顺手补齐概览能力
3. **P3a 国家列 + TOP 统计** —— 低成本拿到 GeoIP 80% 的价值
4. P3b 地图视需求再定

---

# P4 工程提升计划（2026-10 第二轮，安全/性能/分析力）

> 来源：对前轮实现的复盘。按「风险→价值→成本」排序，状态随实施更新。

## 4.1 安全加固 ✅

| 项 | 问题 | 方案 |
|---|---|---|
| 本地 API 鉴权 | 监听 127.0.0.1 但无 Host/Origin 校验，浏览器任意网页可 CSRF 调 `/api/sysmon/uninstall`、`PUT /api/rules`，或 DNS rebinding 打通读写 | 中间件：Host 必须 ∈ {127.0.0.1, localhost, ::1}；非 GET 请求校验 `Sec-Fetch-Site ∈ {same-origin, none, 缺失}` 且 `Origin`（若存在）须为本机；非浏览器工具（curl/Go 客户端）无这些头、保持兼容。**✅ 已实现 + httptest 覆盖（evil Host / cross-site / same-site / Origin null 均拦截）** |
| wevtutil 无超时 | `events/reader.go` 直接 `cmd.Run()`，通道异常时 HTTP 挂死 | 复用 `execWithTimeout`（60s）。**✅ 已实现** |
| GeoIP 端点滥用 | 可被用作任意 IP 查询代理 | 单次上限已有；保持默认关闭。**✅ 维持现状** |

## 4.2 事件管线性能 ✅

- **增量刷新**：自动刷新从「每 5s 全量拉窗口」改为 `since_record_id` XPath 游标（`EventRecordID > N`）只拉新事件、前端按 record_id 合并去重；手动查询仍全量。**✅ 已实现（实测 4s 窗口 52 条增量、游标无重叠）；新事件超过 200 条自动回退全量** 
- 关键字多值 OR：`keyword` 支持 `a|b|c` 任一命中（为检测剧本铺路）。**✅ 已实现 + 单测**
- GeoIP 缓存过期清理（90 天剪枝，防缓存文件无限增长）。**✅ 已实现 + 单测**
- （后置）原生 `EvtQuery/EvtNext` API 替代 wevtutil 子进程，突破 5000 条窗口限制 ⬜ → **✅ P5 已实现（见 5.1）**

## 4.3 分析能力 ✅（部分）

- **检测剧本快捷筛选**：日志页一键应用预设（lsass 凭证访问 / Office 派生进程 / 脚本解释器 / 系统下载器 / 临时目录执行 / 未签名驱动 / DNS / 外联），配合多值关键字。**✅ 已实现（8 个剧本 chips，带提示与激活态）**
- **规则试算 (dry-run)**：规则编辑器内用 Sysmon 条件语义（is/contains any·all/excludes any·all/begin·end with/image/数值比较）对当前已加载事件窗口模拟命中，部署前即可验证规则有效性。**✅ 已实现（编辑器「⚡ 试算」按钮 → 命中统计 + 前 50 条示例，区分记录/排除语义）**
- **配置差异视图**：应用规则时快照 `rules-deployed.json`，脏标记旁一键对比「已部署 vs 当前」（新增/删除/修改）。**✅ 已实现（旧部署无快照时给出友好提示）**
- （后置）P3b 离线 mmdb、bookmark 只看新事件 ⬜ → **✅ P5 已实现（见 5.2/5.4）**

## 4.4 工程质量 ✅

- 版本可追溯：`internal/version` + ldflags 注入（版本/构建时间/rev），状态页与启动日志展示。**✅ 已实现**
- build.bat 可移植化：优先 PATH 中的 go、`-trimpath`、版本注入；去掉硬编码路径依赖。**✅ 已实现**
- CI（GitHub Actions）：build + vet + test + `node --check`。**✅ 已添加 .github/workflows/ci.yml**
- API 中间件/reader 单测补齐（httptest）。**✅ 已实现（安全中间件 13 用例 + 多值关键字 + GeoIP 剪枝）**
- 内置运行日志页：新 tab 直读 `sysmon-gui.log`，方便现场排障。**✅ 已实现（GET /api/applog + 运行日志 tab + 自动刷新）**
- （后置）app.js 模块拆分、api handler 全覆盖测试、清理 manager.go 存量 vet 告警 ⬜ → **✅ P5 已实现（见 5.5）**

## 4.5 体验细节 ✅（部分）

- 事件表列排序（时间/EID 升降序，客户端侧）。**✅ 已实现（表头点击切换，仅平铺视图）**
- （后置）筛选预设保存、暗色模式、事件原始 XML 视图（需原生 API 保留原文）⬜ → **✅ P5 已实现（见 5.4/5.6）**

---

# P5 全量日志与离线能力（2026-10 第三轮，全部完成 ✅）

## 5.1 原生 Event Log API 全量日志 ✅

- `internal/evtapi`：EvtQuery/EvtNext/EvtRender 直调 wevtapi.dll，无子进程开销；wevtutil 保留为回退路径
- fetch 上限 **5000 → 100000**（「加载 10 万条 (全量)」），分组视图/CSV 导出同步放开
- 关键修复：EvtQueryReverseDirection 正确取值 **0x200**（0x100 是正向——曾导致原生读到频道最古老事件）
- 进程谱系三遍扫描：全事件窗口 + EID1 专项窗口 + **引导式 GUID 精确定位**（XPath `EventData[Data[@Name='ProcessGuid']='...']`，祖先链 16 层 + 后代 BFS ≤500，事件洪水下不丢焦点）
- 已知引擎怪癖（已规避）：谓词值含大括号会触发语法错误，须剥离；谓词匹配对旧世代事件不可靠 → 引导查询仅作增强，窗口合并保证兜底

## 5.2 离线 mmdb 解析（P3b 前半） ✅

- `internal/geoip/mmdb.go`：自实现 MaxMind DB 读取器（二进制搜索树 24/28/32bit 记录 + 数据段全类型解码 + 指针解析），支持 GeoLite2-Country/City，**无第三方依赖**
- 放入 `GeoLite2-City.mmdb`（或 Country）即全离线解析，不外发 IP；City 库额外提供坐标（地图打点）
- `/api/geoip/status` 报告离线库状态，前端面板显示「离线/在线」徽标与放置提示
- 单测：树记录/查找/指针解码/中文名提取全绿

## 5.3 P3b 外联地图 ✅

- 内嵌公共领域世界 geojson（Natural Earth 衍生，180 国，257KB）
- 等距圆柱投影 SVG：国家**热力着色**（外联频次）+ City 离线库坐标**红色圆点**（大小=频次，title 提示）
- A2→A3 国家代码映射、深浅色主题适配（CSS 变量）

## 5.4 日志分析体验 ✅

- **只看新事件**：localStorage RecordID 基准 +「标记为已读」，自动刷新配合增量游标零成本跟踪新事件
- **筛选预设**：「存筛选」保存 EID/关键字/时间/条数组合（最多 12 个），chips 一键应用/删除
- **事件原始 XML**：原生拉取的事件 LRU 缓存 1 万条（淘汰最旧方向），详情「查看 XML」直出原文
- **暗色模式**：顶栏一键切换，CSS 变量全量适配，localStorage 持久化

## 5.5 工程收尾 ✅

- app.js 模块化拆分：`js/core.js`（工具/状态）+ `js/rules.js`（规则/试算/差异/导入）+ `js/logs.js`（日志/分组/剧本/预设）+ `js/tree.js`（谱系）+ `js/geo.js`（GeoIP/地图）+ `app.js`（启动/状态页），零重复声明
- api handler 全覆盖 httptest（meta/rules 往返/validate/preview/applog/deployed/templates/config.xml/events 容错，兼容无 Sysmon CI）
- manager.go version.dll `unsafe.Pointer` 存量 vet 告警清零（out-param 改类型化指针）
- **git 仓库初始化**（.gitignore + 里程碑提交），防止再次误操作

## 5.6 遗留已知项

- EvtNext 批次间事件洪水可致 5000+ 窗口轻微漂移（已由引导式查询兜底，非缺陷）
- 谓词查询对「旧世代」事件（重装前/重登录的存量）可能不可靠（引擎行为，靠窗口合并兜底）
- mmdb 需用户自行下载（MaxMind 注册，每月更新 ~6MB）
