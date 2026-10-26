#!/usr/bin/env node
// M14-S6 · GUI 走查入口：解析参数、调度 runWalkthrough、写 JSON 报告、退出码语义。
//
// 用法：
//   node scripts/gui-walkthrough.mjs [--check] [--report <path>] [--timeout <ms>] [--fixture <url>] [--binary <path>] [--force]
//
// 退出码：
//   0  全 pass（warn 不影响）
//   1  至少一个 check fail
//   2  环境不具备（非交互 tty / 无 tauri-driver / 无 GUI）——≠失败
//   3  脚本自身错误（参数非法 / --check 自检失败 / 未捕获异常）
//
// 见 内部文档库 docs/specs/M14-S6-GUI走查.md。

import { writeFileSync } from "node:fs";
import { runWalkthrough, checkSelf } from "./gui-walkthrough-lib.mjs";

function parseArgs(argv) {
  const opts = {
    check: false,
    report: "./gui-walkthrough-report.json",
    timeout: 30000,
    fixture: "http://127.0.0.1:18999/login",
    binary: "src-tauri/target/release/tianshu-relay",
    force: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") opts.check = true;
    else if (a === "--report") opts.report = argv[++i];
    else if (a === "--timeout") opts.timeout = parseInt(argv[++i], 10);
    else if (a === "--fixture") opts.fixture = argv[++i];
    else if (a === "--binary") opts.binary = argv[++i];
    else if (a === "--force") opts.force = true;
    else if (a === "--help" || a === "-h") {
      console.log(`用法: node scripts/gui-walkthrough.mjs [--check] [--report <path>] [--timeout <ms>] [--fixture <url>] [--binary <path>] [--force]
退出码: 0=全绿, 1=有 fail, 2=环境不具备, 3=脚本错误`);
      process.exit(0);
    } else {
      console.error(`未知参数: ${a}（--help 查看用法）`);
      process.exit(3);
    }
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.check) {
    const r = await checkSelf();
    console.log(r.ok ? `self-check ok: ${r.detail}` : `self-check FAIL: ${r.detail}`);
    process.exit(r.ok ? 0 : 3);
  }
  const { report, exitCode } = await runWalkthrough(opts);
  try {
    writeFileSync(opts.report, JSON.stringify(report, null, 2));
    console.log(`报告写入 ${opts.report}`);
  } catch (e) {
    console.error(`写报告失败: ${e.message}`);
  }
  console.log(`exitCode=${exitCode} summary=${JSON.stringify(report.summary)} backlog=${JSON.stringify(report.backlog)}`);
  process.exit(exitCode);
}

main().catch((e) => {
  console.error(`脚本错误: ${e.stack || e.message}`);
  process.exit(3);
});
