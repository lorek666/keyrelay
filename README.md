# 天枢 Relay · 中转站钥匙管家

登录 NewAPI / Sub2API 中转站取 `sk-` 密钥，一键注入到本机各 agent 配置（Codex CLI、Claude Code、OpenCode…），
密钥进本地加密保险库、配置写入可回滚。

> 产品需求：`PRD-天枢Relay.md`　工程流程：`docs/PROCESS.md`（**每一步先写 spec，再实现，再独立复审**）

## 目录结构

```
crates/tianshu-relay-core/     # 纯逻辑库：站点适配器 / 注入器 / 加密保险库 / 存储（不依赖 Tauri）
crates/tianshu-relay-cli/      # 命令行（冒烟 / 迁移等运维入口）
src-tauri/                # Tauri 2 桌面壳：命令与平台胶水
src/                      # React 18 + Vite 前端
scripts/                  # 门禁与守护脚本（gate / check-*）
docs/specs/               # 每步 spec（先写）
docs/reviews/             # 每步复审记录（后写）
docs/evidence/            # 每步门禁与验证证据
docs/ADR/                 # 架构决策
docs/BACKLOG.md           # 范围外问题登记
```

## 环境要求

- Rust 1.89+（`Cargo.toml` 的 `rust-version`，见 ADR-0002；本机 1.99）、Node 20+（本机 24）、pnpm 10+
- macOS 12+ 或 Windows 10+（Tauri 依赖系统 WebView）

## 常用命令

```bash
pnpm install            # 前端依赖（pnpm 11 默认拦截构建脚本，配置见 pnpm-workspace.yaml）
pnpm build              # 前端构建（tsc --noEmit + vite build）
pnpm tauri dev          # 桌面端开发（需先 pnpm install）

cargo test -p tianshu-relay-core    # 核心库测试（含契约测试与注入回滚测试）
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo check -p tianshu-relay        # 桌面壳类型检查（需先 pnpm build 产出 dist/）
```

## 当前进度

已实现至 **M44**（网关验收矩阵与打包），含 NewAPI / Sub2API 适配器、真实 HTTP 传输、
系统钥匙串与本地加密保险库、本地网关（路由 / 熔断 / 负载均衡）、协议翻译（非流式与流式）、
用量账本与成本估算、Agent 级令牌与归因。各步的 spec、复审与门禁证据见 `docs/specs/`、
`docs/reviews/`、`docs/evidence/`；未完成项与遗留问题见 `docs/BACKLOG.md`。

> 2026-10-24 修复波次（分支 `fix-b224-20261024`，未提交）：B-224 清单中的 7 条 P2、
> P3 组与测试有效性缺口已修，详见 `docs/BACKLOG.md` 的 B-224 状态更新行。

## 安全红线（不可违反）

1. 密钥只进本地加密保险库（`vault.db` 密文 + `vault.key`，ADR-0003）；元数据库只存引用（`Store::insert_key` 会拒绝明文）。
2. 任何日志/通知/错误信息先过 `tianshu_relay_core::redact::scrub`。
3. 受管配置文件里只出现 base_url / provider / env 变量名；写密钥进 agent 配置必须先有用户显式同意。
4. 配置写入必须原子、先备份、可字节级回滚；外部改动时拒绝覆盖。

## 安装

从 [Releases](https://github.com/lorek666/keyrelay/releases/latest) 下载最新版：

- macOS：universal dmg（arm64 + x86_64）
- Windows：x64-setup.exe

装好后打开即用；后续更新由应用内更新通道推送。

## 贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。改动流程遵循 `docs/PROCESS.md`（先写 spec，再实现，再独立复审）。

## 许可证

MIT，见 [LICENSE](LICENSE)。
