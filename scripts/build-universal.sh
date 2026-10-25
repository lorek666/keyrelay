#!/usr/bin/env bash
# M14-S5：macOS Universal Binary 构建脚本（PRD §5：≤30MB）。
#
# 用法：
#   bash scripts/build-universal.sh [--check-only]
#
# 退出码：
#   0  成功产出 universal app/dmg 且 ≤30MB（或 --check-only 自检通过）
#   1  产物 >30MB（PRD §5 未达标）
#   2  环境不具备（非 macOS / 缺 rustup/pnpm/lipo）
#   3  脚本自身错误（找不到产物等）
#
# 用 Tauri 的 universal-apple-darwin target（内部 lipo 合并 aarch64 + x86_64），
# 等价于 spec §4.3 的「分别 build + lipo」，但更可靠（不手工替换 .app 内的二进制）。
# 见 docs/specs/M14-S5-Windows-CI.md §4.3。

set -euo pipefail

CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --check-only) CHECK_ONLY=1 ;;
    *) echo "未知参数: $arg" >&2; exit 3 ;;
  esac
done

# 校验宿主是 macOS
if [ "$(uname -s)" != "Darwin" ]; then
  echo "环境不具备：build-universal 仅在 macOS 上运行（收到 $(uname -s)）" >&2
  exit 2
fi

# 依赖检查（--check-only 与真构建共用）
check_deps() {
  local missing=0
  for cmd in rustup pnpm lipo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "缺依赖: $cmd" >&2
      missing=1
    fi
  done
  return $missing
}

if ! check_deps; then
  echo "依赖检查未通过" >&2
  exit 2
fi

# --check-only：只验脚本 + 依赖，不真构建
if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "self-check ok"
  exit 0
fi

# 真构建：universal-apple-darwin target 依赖 aarch64 + x86_64 两个 std
rustup target add aarch64-apple-darwin x86_64-apple-darwin

# tauri build 会自动跑 beforeBuildCommand（pnpm build）
pnpm tauri build --target universal-apple-darwin

# 定位产物：src-tauri 是 workspace 成员时 cargo 把产物放在工作区根 target/ 下，
# 只有独立 crate 时才在 src-tauri/target/ 下；先查工作区根，再回落到旧路径。
APP_DIR=""
for candidate in "target/universal-apple-darwin/release/bundle/macos" "src-tauri/target/universal-apple-darwin/release/bundle/macos"; do
  if [ -d "$candidate" ]; then
    APP_DIR="$candidate"
    break
  fi
done
if [ -z "$APP_DIR" ]; then
  APP_DIR="target/universal-apple-darwin/release/bundle/macos"
fi
APP=$(find "$APP_DIR" -maxdepth 1 -name "*.app" 2>/dev/null | head -n1 || true)
if [ -z "$APP" ]; then
  echo "找不到 universal .app 产物（在 $APP_DIR 下）" >&2
  exit 3
fi

# 测产物大小（PRD §5：≤30MB = 30720 KB，1024 进制）
# 注意：必须用 -s（汇总），裸 du -k 会逐子目录各出一行，SIZE_KB 成多行，
# 后面的整数比较会报 integer expression expected、if 条件按假处理，
# 导致超标也印 PASS（40b7c01 的 build-universal 就是这样假绿的）。
SIZE_KB=$(du -sk "$APP" | cut -f1)
echo "universal app: $APP"
echo "size: ${SIZE_KB} KB（门槛 30720 KB）"

if [ "$SIZE_KB" -gt 30720 ]; then
  echo "FAIL: 产物 ${SIZE_KB} KB > 30720 KB（PRD §5 ≤30MB 未达标）" >&2
  exit 1
fi

echo "PASS: ≤30MB"
