# Sysmon GUI 功能路线图（分析增强篇）

> 依据 nshalabi/SysmonTools (GPLv3) 的交互思路整理。**仅借鉴设计思想，不复制其代码与资源文件**（GPL 许可证不兼容）。
> 现状基线：日志查看页已支持 EID/关键字/时间筛选、事件详情展开、按字段快速下钻（🔍）、哈希/IP/域名 VirusTotal 跳转。
>
> **实施进度（2026-10）**：P1 / P2 / P3a 已全部落地 ✅，P3b 暂缓。

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

## 4.2 事件管线性能 ✅（部分）

- **增量刷新**：自动刷新从「每 5s 全量拉窗口」改为 `since_record_id` XPath 游标（`EventRecordID > N`）只拉新事件、前端按 record_id 合并去重；手动查询仍全量。**✅ 已实现（实测 4s 窗口 52 条增量、游标无重叠）；新事件超过 200 条自动回退全量** 
- 关键字多值 OR：`keyword` 支持 `a|b|c` 任一命中（为检测剧本铺路）。**✅ 已实现 + 单测**
- GeoIP 缓存过期清理（90 天剪枝，防缓存文件无限增长）。**✅ 已实现 + 单测**
- （后置）原生 `EvtQuery/EvtNext` API 替代 wevtutil 子进程，突破 5000 条窗口限制 ⬜

## 4.3 分析能力 ✅（部分）

- **检测剧本快捷筛选**：日志页一键应用预设（lsass 凭证访问 / Office 派生进程 / 脚本解释器 / 系统下载器 / 临时目录执行 / 未签名驱动 / DNS / 外联），配合多值关键字。**✅ 已实现（8 个剧本 chips，带提示与激活态）**
- **规则试算 (dry-run)**：规则编辑器内用 Sysmon 条件语义（is/contains any·all/excludes any·all/begin·end with/image/数值比较）对当前已加载事件窗口模拟命中，部署前即可验证规则有效性。**✅ 已实现（编辑器「⚡ 试算」按钮 → 命中统计 + 前 50 条示例，区分记录/排除语义）**
- **配置差异视图**：应用规则时快照 `rules-deployed.json`，脏标记旁一键对比「已部署 vs 当前」（新增/删除/修改）。**✅ 已实现（旧部署无快照时给出友好提示）**
- （后置）P3b 离线 mmdb、bookmark 只看新事件 ⬜

## 4.4 工程质量 ✅（部分）

- 版本可追溯：`internal/version` + ldflags 注入（版本/构建时间/rev），状态页与启动日志展示。**✅ 已实现**
- build.bat 可移植化：优先 PATH 中的 go、`-trimpath`、版本注入；去掉硬编码路径依赖。**✅ 已实现**
- CI（GitHub Actions）：build + vet + test + `node --check`。**✅ 已添加 .github/workflows/ci.yml**
- API 中间件/reader 单测补齐（httptest）。**✅ 已实现（安全中间件 13 用例 + 多值关键字 + GeoIP 剪枝）**
- 内置运行日志页：新 tab 直读 `sysmon-gui.log`，方便现场排障。**✅ 已实现（GET /api/applog + 运行日志 tab + 自动刷新）**
- （后置）app.js 模块拆分、api handler 全覆盖测试、清理 manager.go 存量 vet 告警 ⬜

## 4.5 体验细节 ✅（部分）

- 事件表列排序（时间/EID 升降序，客户端侧）。**✅ 已实现（表头点击切换，仅平铺视图）**
- （后置）筛选预设保存、暗色模式、事件原始 XML 视图（需原生 API 保留原文）⬜
