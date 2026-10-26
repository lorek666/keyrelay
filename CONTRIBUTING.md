# 贡献指南

欢迎提 Issue 和 PR。本仓库实行 **spec 先行** 的工程流程：每一步先写 spec，再实现，再独立复审（流程细节在内部文档库）。PR 请尽量按这个节奏来，大改动先开 Issue 讨论。

## 本地开发

```bash
pnpm install            # 前端依赖
pnpm build              # 前端构建（tsc --noEmit + vite build）
pnpm tauri dev          # 桌面端开发

cargo test -p tianshu-relay-core    # 核心库测试
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

完整命令与环境要求见 `README.md`。

## PR 检查清单

- [ ] CI 两门禁通过（`gate-macos`、`gate-windows`，分支保护强制要求）
- [ ] 有 spec 或复审记录的改动已按 spec 先行流程同步留存（内部文档库）
- [ ] **没有提交任何真实密钥、token、证书或账号信息**；日志、截图、测试固件先脱敏
- [ ] 改动了用户可见行为的，同步更新了 README 或相关文档

## 安全问题不要公开提

疑似安全漏洞（尤其涉及密钥外泄）请按 `SECURITY.md` 私下报告，不要直接开公开 Issue。
