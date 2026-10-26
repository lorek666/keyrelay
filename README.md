# 天枢 Relay · 中转站钥匙管家

> 登录 NewAPI / Sub2API 中转站，自动拿 `sk-` 密钥，一键注入本机各 agent 并长期托管。

你手里有两三个中转站账号，本机又装了好几个 AI 编程 agent——每次换站、换 key 都要逐个改配置文件，改错一个就是静默 401，额度用完才发现没钱。天枢 Relay 就是把这套手工活收进一个桌面 App：站点侧取 key、管 key、看余额，agent 侧一键注入、随时回滚。

- **下载最新版**：[Releases](https://github.com/lorek666/keyrelay/releases/latest)（macOS universal dmg / Windows x64-setup.exe）
- **当前版本**：v0.2.0
- **适用人群**：手里 2–6 个中转站账号、本机 3–8 个 agent 的重度 AI 编码用户；以及给团队成员发 key 的自建站站长。

## 它解决什么

| 痛点 | 之前的做法 | 用天枢 Relay 之后 |
| ---- | ---- | ---- |
| 密钥与 agent 配置手工同步 | 换站/换 key 要改 N 个文件，改错就静默 401 | 一次点击注入全部已绑定 agent，写前先出 diff 预览 |
| 站点登录态易失效 | 每次重新登录、过验证码 | 会话失效被检出并提示，登录走官方页面兜底 |
| 密钥散落、无生命周期 | 不知道哪把 key 在用、哪把该回收 | 跨站 key 表格：站点、分组、状态、用量、绑定 agent 一目了然 |
| 余额/配额不透明 | 跑到 403 才发现没钱 | 余额低于阈值提前告警，不用等到额度耗尽 |
| 多站切换成本高 | 单站故障时手工切站 | 网关层切后端，agent 侧零改动；或一键重注入 |
| 明文泄漏面大 | key 明文落盘进 N 个配置文件 | 密钥只进本地加密保险库；网关模式下 agent 侧连明文 key 都没有 |

## 功能一览

- **站点接入**：填 `base_url` 自动识别站点类型（NewAPI 系 / Sub2API / 自定义 OpenAI 兼容），登录、列出已有 key 与余额。支持 TOTP 二次验证；撞上验证码时不绕过，走内嵌 WebView 官方页面手动过一次。
- **密钥管理**：跨站新建、查看、回收 key；站点侧分组与倍率拉取后供选择；新建 key 默认按 `<应用>/<agent>/<日期>` 命名，站点侧一眼看出给谁用；解绑默认只解绑不回收，可恢复。
- **一键注入与回滚**：每个 agent 一个注入器：探测安装 → 生成 diff → 原子写入 → 回读校验；写前自动备份，注入后 agent 起不来可一键回滚到字节一致的旧配置；只改受管字段，不动你手工写过的其他内容，格式与注释原样保留。
- **本地网关**：本机起一个 OpenAI / Anthropic 兼容端口（默认 `127.0.0.1:8787`），agent 只连本地、只用本地签发的 `local-` token，真实站点 key 不出保险库；上游故障自动切换、熔断后探活回归。
- **多站路由与成本**：按余额健康度、倍率、延迟（EWMA）选路；分 agent 路由规则；重试预算与分站点超时；硬预算（v1 按 USD 计）；账单对账与用量成本估算。
- **监控告警**：余额、用量、登录态、模型列表变化统一看板；余额低于阈值、用量异常跳变、登录态失效时提醒；断网时显示 `stale` 标记，不阻塞界面。
- **安全**：见下文[安全模型](#安全模型)。
- **运维**：配置漂移检测（启动时发现目标文件被外部改动会提示）、会话保活、密钥轮换提醒、诊断包一键导出、应用内自动更新、界面中/英切换。

## 安装

从 [Releases](https://github.com/lorek666/keyrelay/releases/latest) 下载：

- **macOS**：universal dmg（arm64 + x86_64），要求 macOS 12+
- **Windows**：x64-setup.exe，要求 Windows 10/11

装好后打开即用；后续更新由应用内更新通道推送（设置里可开关自动更新）。

## 快速上手

### 1. 接入站点

输入站点 URL → App 自动识别站点类型 → 输入账号密码（需要时输入 6 位 TOTP 码）→ 登录成功后自动列出已有 key 与余额。

> TOTP 说明：出于安全，本产品**不在本机保存 TOTP 密钥**，每次登录需要你输入 6 位码；会话保持交给会话凭证，而不是复制第二因子。

### 2. 拿一把 key

选中已有 key，或新建一把：选分组（展示倍率）、额度与过期时间。新建后 key 立即可用。

### 3. 注入 agent

在 Agent 页选择已检测到的 agent → 选 key → **先看 diff 预览**，确认无误点应用。注入后 agent 可直接跑通；需要重启的 agent 会在界面标注（本产品不替你杀进程重启，以免打断正在跑的任务）。

### 4. 日常与回滚

- 额度告警来了：在 App 内切到另一个站点的 key，一键重新注入全部已绑定 agent。
- 注入后 agent 起不来：在变更历史里点回滚，恢复到注入前字节一致的配置。
- 想彻底不让明文 key 落盘：改走本地网关模式，agent 侧只留 `local-` token，换站只需改网关后端。

## 界面导览

| 区域 | 看什么、做什么 |
| ---- | ---- |
| 指挥舱 | 站点卡片（余额、登录态、key 数、最近告警）+ 全局快捷操作 |
| 流量 | 网关请求与各站用量趋势 |
| 成本 | 预算、账单对账、模型价格与用量成本估算 |
| 健康 | 网关与各站健康状态、密钥健康探测、故障切换记录 |
| 资产 | 跨站 key 表格与各 key 的绑定 agent |
| 投递 | 已检测到的 agent、当前绑定、注入/回滚、配置 diff 预览 |
| 设置 | 刷新间隔、告警阈值、代理、自启与常驻、自动更新、语言、诊断导出 |

关键交互约束：**所有写操作先出 diff**；危险操作（回收 key、覆盖手工改动）二次确认。

## 支持的站点

| 类型 | 说明 |
| ---- | ---- |
| NewAPI 系 | NewAPI 及 one-api / one-hub / veloera / donehub 等兼容实现 |
| Sub2API | Sub2API 实例（含 TOTP / step-up 二次确认） |
| 自定义 OpenAI 兼容 | 兼容 OpenAI 风格的站点（只读余额不可用时降级） |

登录方式：NewAPI 走加密登录，Sub2API 走账号登录；会话凭证保存在本地，启动时静默校验，失效会标记并提示，不出现静默 401。

## 支持的 Agent

投递覆盖 20 个渠道（19 个可直写，1 个例外见注）：

| Agent | 备注 |
| ---- | ---- |
| Codex CLI | `auth.json` 与 `config.toml` 一次投递（同一把 key 走两个文件） |
| Claude Code、Claude Desktop | |
| OpenCode | `.json` 与 `.jsonc` 是两个落点，预览里自选其一，产品不猜优先级 |
| Gemini CLI、Grok、OpenClaw、Hermes、MCode、Pi | |
| Cursor、Cline、Qwen Code、DeepSeek、Trae、MiMoCode、DeepSeek Harness | |
| Cline 桌面版 | ⚠️ 暂不支持文件直写，请走 `cline auth` CLI |

每个 agent 的生效策略不同（有的新会话即生效，有的需重启），注入前界面会标注。

## 本地网关

网关模式是为“不想让明文 key 落盘”准备的：

- 默认监听 `127.0.0.1:8787`（仅 loopback），agent 侧 base_url 指到本地即可。
- 兼容端点：`POST /v1/chat/completions`、`POST /v1/responses`、`POST /v1/messages`、`GET /v1/models`（含 SSE 流式透传）。
- agent 只用本地签发的 `local-` token（可撤销）；真实站点 key 留在保险库。
- 路由：站点/模型路由表，上游 429 / 5xx 按优先级故障切换；连续失败触发熔断，冷却后探活回归。
- 成本控制：硬预算（v1 按 USD 计）、重试预算、分站点超时、分 agent 路由规则。
- 请求日志默认只记元数据，不记正文。

## 安全模型

- **密钥只进本地加密保险库**：`vault.db` 存 AES-256-GCM 密文，`vault.key` 存设备绑定的数据密钥；元数据库只存引用，`Store::insert_key` 会拒绝明文。
- **日志零明文**：任何日志、通知、错误信息先过脱敏（`sk-…`、`nap-…`、PAT、`Authorization` 头一律打码），脱敏在写日志前完成。
- **写操作可审计、可回滚**：原子写（临时文件 + rename）+ 写前备份 + 变更 journal；回滚后文件与注入前字节一致。
- **受管字段隔离**：只改受管字段；配置文件里的其他内容、格式与注释原样保留；重名冲突先报冲突让用户确认。
- **写密钥需你同意**：把密钥写进 agent 配置必须先有你的显式同意；外部改动过的目标文件不会被静默覆盖。
- **导出加密**：导出包为 AES-GCM 加密包（口令派生），默认不含站点密码；无口令不可读。
- **内存卫生**：敏感字符串用 `zeroize` 清零；不写入剪贴板历史。
- **隐私**：默认零遥测，不采集 prompt 正文、不采集密钥，数据默认只在本机；遥测开关默认关闭且明示发送内容。

### 本产品不做的事

- 不做站点侧管理后台（不改 NewAPI / Sub2API 源码，不做渠道/用户管理）
- 不代他人注册、不批量养号、不绕过站点风控与付费
- 不做公共 SaaS（无服务端、无账号体系、本地优先）
- 不做流量劫持式 MITM（本地网关是显式代理，不是透明劫持）
- 不保存站点管理员凭证；前端包与仓库不含任何应用密钥

## 常见问题

**Q：撞上验证码怎么办？**
A：不绕过。App 弹出内嵌 WebView 走官方页面，你手动过一次，App 抓取会话 Cookie 后继续。

**Q：TOTP 每次都要输吗？**
A：是的。TOTP 密钥不存本机，这是刻意的安全取舍：把第二因子长期凭据复制到本机等于把 2FA 降级为 1FA。

**Q：注入后 agent 需要重启吗？**
A：看 agent。有的新会话即生效，有的需要重启；注入前界面会标注。本产品不替你重启 agent 进程，以免打断正在跑的任务。

**Q：站点侧手工删了 key 会怎样？**
A：下次刷新时本地会把这把 key 标记为缺失，不会静默用一把不存在的 key。

**Q：解绑 agent 会同时回收站点侧的 key 吗？**
A：默认不会。解绑只解绑，可恢复；需要回收时解绑会提示你确认。

**Q：换站一定要每个 agent 手工改吗？**
A：不用。网关模式下改网关后端即可，agent 侧零改动；直写模式下一键重新注入全部已绑定 agent。

**Q：卸载后残留怎么办？**
A：钥匙串/保险库条目与本地数据可一键清理；诊断包导出也是脱敏后的，不含密钥明文。

**Q：支持 Linux 吗？**
A：尽力而为，不作为验收项；当前发布目标是 macOS 与 Windows。

**Q：安全漏洞怎么报？**
A：不要公开提 Issue，按 [SECURITY.md](SECURITY.md) 走 GitHub 私密漏洞上报。

## 开发

本节面向想改代码的贡献者；普通用户用上面[安装](#安装)即可。

### 环境要求

- Rust 1.89+（`Cargo.toml` 的 `rust-version`；本机 1.99）、Node 20+（本机 24）、pnpm 10+
- macOS 12+ 或 Windows 10+（Tauri 依赖系统 WebView）

### 常用命令

```bash
pnpm install            # 前端依赖（pnpm 11 默认拦截构建脚本，配置见 pnpm-workspace.yaml）
pnpm build              # 前端构建（tsc --noEmit + vite build）
pnpm tauri dev          # 桌面端开发（需先 pnpm install）

cargo test -p tianshu-relay-core    # 核心库测试（含契约测试与注入回滚测试）
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo check -p tianshu-relay        # 桌面壳类型检查（需先 pnpm build 产出 dist/）
```

附带命令行（`tianshu-relay-cli`）做冒烟与迁移等运维操作。

### 目录结构

```
crates/tianshu-relay-core/     # 纯逻辑库：站点适配器 / 注入器 / 加密保险库 / 存储（不依赖 Tauri）
crates/tianshu-relay-cli/      # 命令行（冒烟 / 迁移等运维入口）
src-tauri/                # Tauri 2 桌面壳：命令与平台胶水
src/                      # React 18 + Vite 前端
scripts/                  # 门禁与守护脚本（gate / check-*）
USER-MANUAL.md            # 用户使用手册
```

### 贡献流程

工程流程：**每一步先写 spec，再实现，再独立复审**。PR 前请读 [CONTRIBUTING.md](CONTRIBUTING.md)，并确认 CI 两门禁（`gate-macos`、`gate-windows`）通过。

## 相关文档

- 用户手册：[USER-MANUAL.md](USER-MANUAL.md)
- 安全政策：[SECURITY.md](SECURITY.md)
- 行为准则：[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## 许可证

MIT，见 [LICENSE](LICENSE)。
