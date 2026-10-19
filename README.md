# Sysmon GUI

[![CI](https://github.com/chenflux/sysmon-gui/actions/workflows/ci.yml/badge.svg)](https://github.com/chenflux/sysmon-gui/actions/workflows/ci.yml)
[![Release](https://github.com/chenflux/sysmon-gui/actions/workflows/release.yml/badge.svg)](https://github.com/chenflux/sysmon-gui/actions/workflows/release.yml)
[![GitHub release](https://img.shields.io/github/v/release/chenflux/sysmon-gui)](https://github.com/chenflux/sysmon-gui/releases)

Windows 下 [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) 的可视化部署、规则编辑与日志调查工具。**单文件、零外部依赖**（前端资源与地图数据全部内嵌），面向应急响应与威胁狩猎场景。

## 功能特性

### 状态与部署
- 一键安装 / 卸载 / 重装 / 应用规则（自动 UAC 提权、同名第三方服务识别与忽略、事件清单瞬时失败自动重试）
- **首次运行自动从微软官网下载 Sysmon**（x64 / x86 / ARM64），无需手工准备
- 规则脏标记与「已部署 vs 当前」差异对比

### 规则编辑
- 可视化条件组编辑（组内与/或、多组间或），基于本机 Sysmon 官方 schema 实时校验
- XML 预览 / 下载 / 导入（支持任意第三方配置，如 SwiftOnSecurity）
- **规则试算**：用当前已加载日志模拟规则命中，部署前即可验证
- 内置 26 条「快速检测基线 v2」默认规则（全检测面、签名 AND 排除、IPv4+IPv6、管道/WMI/ADS）

### 日志调查
- **全量日志**：原生 Event Log API（wevtapi）直读，单窗口最高 10 万条，无 5000 条限制
- **进程谱系树**：按 GUID 引导式精确定位（祖先链 / 子进程树 / 关联事件时间线），不受事件洪水影响
- 层级分组透视（进程 / 事件类型 / 用户）、时间/EID 排序、检测剧本一键筛选（lsass 访问、Office 派生、下载器等 8 个预设）
- 关键字多值 OR（`a|b|c`）、增量刷新（RecordID 游标）、只看新事件（已读基准）、筛选预设保存
- 事件原始 XML 查看、哈希 / IP / 域名 VirusTotal 快捷跳转
- **GeoIP**：可选离线 MaxMind 库（自研 mmdb 解析器，支持 GeoLite2-Country/City）或在线批量查询（默认关闭）；外联国家 TOP10 与世界地图热力/坐标打点
- 暗色模式、CSV 导出、程序内置运行日志页

### 安全
- 本地 API 防 CSRF / DNS rebinding（Host 白名单 + Sec-Fetch-Site/Origin 校验）
- wevtutil 调用全部限时；规则与部署操作留痕（sysmon-gui.log）

## 快速开始

**安装**：从 [Releases](https://github.com/chenflux/sysmon-gui/releases) 下载最新 `sysmon-gui-v*-win-x64.zip`（哈希见 `sha256.txt`），解压后：

1. 运行 `sysmon-gui.exe`（首次会弹 UAC 提权）
2. 若本机没有 Sysmon，程序会询问是否从微软官网自动下载（不同意则退出）
3. 点击「安装 Sysmon 并应用规则」即可开始采集
4. 「日志查看」页查询事件，点开详情可下钻进程谱系 / GeoIP / VirusTotal

命令行参数：

```
sysmon-gui.exe [-ui window|web|none] [-addr 127.0.0.1:8791] [-data DIR] [-no-elevate]
```

## 构建

要求：Go 1.24+、Windows 10+。

```
build.bat        # 产物 dist\sysmon-gui.exe（版本号经 ldflags 注入）
go test ./internal/...   # 单元测试
```

CI（GitHub Actions）：构建 + vet + 测试 + JS 语法检查。

## 目录结构

```
main.go               入口（WebView2 窗口 / 浏览器 / 无头三模式）
internal/
  evtapi/             原生 Windows 事件日志 API（EvtQuery/EvtNext/EvtRender）
  events/             查询/分页/多值关键字/进程谱系树/原始XML缓存
  geoip/              在线批量查询+磁盘缓存 / 自研 mmdb 离线解析
  sysmon/             安装/卸载/重试/服务甄别、规则模型/XML 生成与导入、schema
  api/                HTTP 服务 + 安全中间件
  version/            构建版本注入
web/                  前端（原生 HTML/JS/CSS，go:embed 内嵌；js/ 按模块拆分）
ROADMAP.md            功能路线图与实施记录
```

## 隐私说明

- GeoIP 在线模式会把外联 IP 批量提交至 ip-api.com（本地缓存 30 天）；放入 `GeoLite2-City.mmdb` / `GeoLite2-Country.mmdb` 即完全离线，不产生任何外发请求
- 除上述可选功能外，程序不联网、不上报任何数据

## 许可证

[GPL-3.0](LICENSE)

## 致谢

- [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)（首次运行自动从官网获取）
- 世界地图数据：[Natural Earth](https://www.naturalearthdata.com/) 衍生的公共领域 GeoJSON
