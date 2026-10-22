#!/usr/bin/env bash
#
# M6-S5 变异验证（Lead 执行；章程 §6.3）
#
# 目的：把「这条测试覆盖了那处修复」从自证变成可证伪的事实——**回退某一处修复，
# 指出具体哪条测试会以什么形态变红**。跑不出红，就说明那条断言没有牙。
#
# 三条纪律（来自 B-38 / B-43 的教训）：
# 1. **`CARGO_TARGET_DIR` 必须与主工作区隔离**：被变异的代码若编译失败，主 `target/`
#    里会留下**旧**产物，后续测试可能跑出与自己相反的结论。
# 2. **每次变异前后取 sha256**：变异没匹配上（哈希没变）就判本次**无效并停止**，
#    否则「测试还是绿的」会被误读成「这条断言没有牙」——这是假阴性的经典来源。
# 3. **还原用 `/tmp` 的副本 `cp` 回来，并 `cmp` 逐字节确认**；**不用** `git checkout --`：
#    这棵树上的改动都还没提交，回滚到 HEAD 会毁掉整个波次的成果。
#
# 用法：
#   CARGO_TARGET_DIR=/tmp/kr-mut-target scripts/m6s5-mutation-probes.sh
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

if [ -z "${CARGO_TARGET_DIR:-}" ]; then
  echo "拒绝运行：必须先显式指定隔离的 CARGO_TARGET_DIR（纪律 1）" >&2
  exit 2
fi
case "$CARGO_TARGET_DIR" in
  "$REPO_ROOT"/target) echo "拒绝运行：CARGO_TARGET_DIR 指向主工作区 target/（纪律 1）" >&2; exit 2 ;;
esac

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kr-mut.XXXXXX")"
# 不用 `rm -rf "$WORK"` 收尾：原始输出是本次验证的证据，要留在仓库里。
# 备份文件留在临时目录（不进仓库），退出时只删备份、保留 `.out` 日志已复制后的目录。
LOG_DIR="$REPO_ROOT/docs/evidence/m6s5-mutation"
mkdir -p "$LOG_DIR"
cleanup() {
  rm -f "$WORK"/*.bak
}
trap cleanup EXIT

echo "# M6-S5 变异验证"
echo
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
echo "工作副本（备份/日志）：$WORK"
echo

sha() { shasum -a 256 "$1" | awk '{print $1}'; }

probe() {
  local name="$1" file="$2" pattern="$3" cargo_args="$4"
  local backup="$WORK/$name.bak"
  local before after

  before="$(sha "$file")"
  cp "$file" "$backup"

  # shellcheck disable=SC2016  # 模式由调用方以单引号给出，故意不让 shell 展开
  perl -0777 -pi -e "$pattern" "$file"
  after="$(sha "$file")"

  echo "## 探针 $name"
  echo
  echo '```'
  echo "文件：$file"
  echo "变异前 sha256：$before"

  if [ "$before" = "$after" ]; then
    echo "变异后 sha256：$after"
    echo "!! 变异未生效（哈希没变）——本次结论无效，已跳过。"
    echo '```'
    cp "$backup" "$file"
    cmp -s "$backup" "$file" && echo "（已逐字节还原）"
    return 1
  fi

  echo "变异后 sha256：$after  ← 已改变，变异生效"
  echo "变异：$pattern"
  echo "命令：cargo test $cargo_args"
  echo '```'
  echo

  # shellcheck disable=SC2086  # 参数按空格拆成多个 cargo 参数
  local out
  out="$(cargo test $cargo_args 2>&1)"
  echo "$out" > "$WORK/$name.out"

  echo '```'
  echo "$out" | grep -E '^(test |error|warning: unused|test result|failures:|---- )' | head -40
  echo '```'
  echo
  echo "原始输出留档：docs/evidence/m6s5-mutation/$name.out"
  echo

  cp "$backup" "$file"
  if cmp -s "$backup" "$file"; then
    # 注意花括号：字符串里紧跟全角括号时，`$before（` 会被 bash 当成变量名的一部分
    # （多字节字符不是标识符分隔符），在 `set -u` 下直接报 unbound variable 并中断脚本。
    echo "还原：逐字节一致（${before}）"
  else
    echo "!! 还原失败：$file 与备份不一致，请立刻人工处理" >&2
    return 2
  fi
  echo
  echo "---"
  echo
}

probe \
  "P1-W1-drift" \
  "crates/tianshu-relay-core/src/service.rs" \
  's/drift: drift_by_site\.get\(&site\.id\)\.cloned\(\)\.unwrap_or_default\(\)/drift: Vec::new()/g' \
  "-p tianshu-relay-core --test notify_wiring"

probe \
  "P2-W1-rotation" \
  "crates/tianshu-relay-core/src/service.rs" \
  's/rotation_due: rotation_by_site\.get\(&site\.id\)\.cloned\(\)\.unwrap_or_default\(\)/rotation_due: Vec::new()/g' \
  "-p tianshu-relay-core --test notify_wiring"

probe \
  "P3-baseline-copies-current" \
  "crates/tianshu-relay-core/src/service.rs" \
  's/sites\.push\(neutral_site\(site\)\);/sites.push(site.clone());/' \
  "-p tianshu-relay-core --test notify_wiring"

probe \
  "P4-null-journal-id" \
  "crates/tianshu-relay-core/src/store/mod.rs" \
  "s/COALESCE\(b\.journal_id, ''\) AS journal_id,/b.journal_id,/" \
  "-p tianshu-relay-core --test rotation_run"

probe \
  "P5-unmapped-refusal" \
  "crates/tianshu-relay-core/src/service.rs" \
  's/if !unmapped\.contains\(&binding\.agent_id\) \{/if false {/' \
  "-p tianshu-relay-core --test rotation_run"

probe \
  "P6-rotation-export" \
  "crates/tianshu-relay-core/src/lib.rs" \
  's/^pub mod rotation;$/\/\/ pub mod rotation;/m' \
  "-p tianshu-relay-core --test rotation"

probe \
  "P7-missing-site-fill" \
  "crates/tianshu-relay-core/src/service.rs" \
  's/let baseline = filled_baseline\(prev, &snapshot\);/let baseline = prev.unwrap_or(crate::notify::Snapshot { sites: Vec::new() });/' \
  "-p tianshu-relay-core --test notify_wiring"

echo "# 全部探针结束"
echo
echo "原始输出已复制到 $LOG_DIR/："
cp "$WORK"/*.out "$LOG_DIR"/ 2>/dev/null
ls -1 "$LOG_DIR"
