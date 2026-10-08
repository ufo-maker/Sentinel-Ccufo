# Sentinel-Ccufo

> Windows SMB 端口暴露实时监控与一键处置工具

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011-blue.svg)](https://learn.microsoft.com/zh-cn/dotnet/core/compatibility/windows)
[![Runtime](https://img.shields.io/badge/.NET-8.0-purple.svg)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Language](https://img.shields.io/badge/language-C%23-blue.svg)](src)

---

## 这是什么

一款常驻Windows 托盘的轻量安全工具，专门盯防 **SMB（445 端口）暴露到公网** 这一类风险，并提供一键处置。

## 下载

最新版本：**[v1.0.0](https://github.com/ufo-maker/Sentinel-Ccufo/releases/latest)** ｜ [CNB 镜像](https://cnb.cool/FFUFO/Sentinel-Ccufo)

直接下载 `Sentinel-Ccufo-Setup-1.0.0.exe`（44 MB，需管理员权限）

它解决的是一个很具体、也很容易被误判的问题：

> Windows 弹出「密码正确却提示密码错误」，很多人会去怀疑密码记错了、键盘坏了、
> 甚至怀疑系统被黑了 —— 真因往往是**账户因连续爆破失败被锁定**，
> 而锁定状态下系统**根本不校验密码**就直接拒绝。

```
Microsoft Edge 正在尝试填写密码。键入你的 Windows 密码以允许此操作。
引用的账户当前已锁定，且可能无法登录。← 真正的原因在这里
```

## 核心能力

| 能力 | 说明 |
|---|---|
| **实时监控** | 公网入站连接 / 账户锁定状态 / 爆破尝试次数 / 入侵成功判定 / 防护规则状态 |
| **威胁溯源** | 展示攻击源 IP、归属地、活跃连接数、**它尝试过的账户名** |
| **一键加固** | 解锁账户 → 启用局域网专用防护 → 封禁全部威胁 IP，一条命令链完成 |
| **命令透明** | 每一步执行的真实命令与完整输出都在界面里可查、可复制、可导出 |
| **风险评分** | 0-100 分四档评级，仪表盘直观呈现 |

## 技术特点

### 原生 API 优先

连接表与账户状态走 Win32 API直读内核数据，**不起子进程**：

```
GetExtendedTcpTable (iphlpapi.dll)   读TCP 连接表< 1 ms
NetUserGetInfo  (netapi32.dll)      读账户锁定状态   < 1 ms
NetworkInterface.GetAllNetworkInterfaces()  读网卡信息  < 1 ms
```

### 分层调度

按数据的**真实变化频率**决定轮询间隔，而非一刀切：

| 数据 | 变化频率 | 轮询间隔 |
|---|---|---|
| 公网入站连接（告警源） | 秒级 | **2 秒** |
| 账户锁定状态 | 变化即重要 | **2 秒** |
| 安全日志 | 变化慢 | 15 秒 |
| 防火墙规则 | 极少变 | 60 秒 |
| 公网 IP | 几乎不变 | **10 分钟** |

### 输出分级

命令**永远完整显示**（审计依据不缺失），输出按量级分层处理：

| 输出量级 | 处理方式 |
|---|---|
| ≤ 5 KB | 界面内联完整显示 |
| 5–50 KB | 掐头去尾（头 18 行 + 尾 12 行） |
| > 50 KB | 自动落盘 + 摘要 + **点击打开完整文件** |

## 性能表现

以 `.NET 8 + WinForms` 原生实现，相比 Electron 方案：

| 指标 | Electron 版 | 本项目 |
|---|---|---|
| 单轮采集耗时 | 6269 ms | **2.3 ms** |
| CPU 占用 | 125%（持续满载） | **0.10%** |
| 常驻内存 | 1100 MB | **42 MB** |
| 进程数 | 4 个 | **1 个** |

## 安装

1. 运行 `Sentinel-Ccufo-Setup-1.0.0.exe`
2. 选择安装目录（默认 `C:\Program Files\Sentinel-Ccufo`）
3. 勾选「开机自动启动（托盘常驻）」可持续后台监控
4. 安装完成后程序启动即最小化到托盘

> 需要管理员权限（修改防火墙规则与解锁账户所必需）
> 未做代码签名，Windows SmartScreen 提示时选择「更多信息 →仍要运行」

### 静默安装

```cmd
Sentinel-Ccufo-Setup-1.0.0.exe /S
```

## 使用

双击托盘图标唤出主界面。左栏是安全概览与网络信息，中栏是威胁源与一键处置，右栏是命令执行记录。

| 操作 | 说明 |
|---|---|
| 拖动栏宽 | 栏间分隔条可拖动，布局记入 `%APPDATA%\Sentinel-Ccufo.ini` |
| 双击标题栏 | 最大化 / 还原 |
| `Ctrl +` / `Ctrl -` | 界面缩放 85%–160% |
| 点击左栏信息 | 复制到剪贴板 |
| 点「日志目录」 | 打开落盘的完整输出目录 |

## 从源码构建

环境要求：Windows 10/11 + .NET 8 SDK

```bash
#编译
dotnet build src/Sentinel-Ccufo.csproj -c Release

# 发布自包含单文件（无需目标机预装 .NET）
dotnet publish src/Sentinel-Ccufo.csproj -c Release -r win-x64 \
  --self-contained true -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true -o publish/

# 打包安装程序（需 NSIS）
makensis build/installer.nsi
```

## 常见问题

<details>
<summary><b>为什么账户会莫名锁定？</b></summary>

445 端口暴露在公网被扫描器持续爆破，累计失败达阈值后账户锁定。锁定状态下系统不校验密码，因此正确密码同样被拒绝。用本工具确认入站连接数与爆破来源即可定位。
</details>

<details>
<summary><b>封了 IP 还会复发吗？</b></summary>

会。逐个封 IP 是治标，扫描器换 IP 后仍会复发。根治需**启用「局域网专用防护」**（阻断公网入站），并**拆除路由器上的 445 端口转发**。
</details>

<details>
<summary><b>需要一直开着吗？</b></summary>

建议常驻托盘。监控本身几乎不耗资源（CPU 0.1% / 内存 42 MB），关闭则失去实时告警能力。
</details>

## 安全声明

本工具**只读监控 + 用户确认后处置**，不会自动执行任何变更。所有变更操作均在界面中逐步展示真实命令与输出。

「紧急加固」会修改防火墙规则并解锁账户 —— 这些都是防御性动作，但执行前请确认你理解其影响。

## 许可

MIT