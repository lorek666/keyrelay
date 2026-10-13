//! M7-S3 集成测试 · Continue 通道（`~/.continue/config.yaml` 的标记块）。
//!
//! 本文件是 spec §10.1 的落地：**块外字节不变**用「逐字节切片相等 + sha256 相等」两层断言，
//! 夹具刻意包含会让「顺手重写整份文件」暴露的形态（用户自己的条目、行内注释、
//! 不以换行结尾、CRLF、中文/emoji）。

use std::fs;
use std::path::{Path, PathBuf};

use keyrelay_core::delivery::continue_yaml::{ContinueWriter, BLOCK_BEGIN, BLOCK_END};
use keyrelay_core::delivery::opencode::OpenCodeWriter;
use keyrelay_core::delivery::{resolve_for, resolve_for_binding, DeliveryChannel, DeliveryWriter};
use keyrelay_core::error::Error;
use keyrelay_core::inject::sha256_hex;

const SECRET: &str = "sk-continue-INT-0123456789abcdef";
const ROTATED: &str = "sk-continue-INT-ROTATED-999999";
const BASE: &str = "https://relay.example.com/v1";
const MODEL: &str = "gpt-4o";

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("临时目录")
}

fn writer(dir: &Path, base_url: &str, model: Option<&str>) -> ContinueWriter {
    ContinueWriter::with_path(dir.join("config.yaml"), base_url, model)
}

/// 按块边界切出「块外」的前缀与后缀。
///
/// 前缀切到**块首行的行首**（即把块行的缩进算作块的一部分——与 `locate_block` 同一口径），
/// 后缀从结束标记那一行的行尾之后算起。
fn outside(text: &str) -> (String, String) {
    let marker = text.find(BLOCK_BEGIN).expect("应有开始标记");
    let bytes = text.as_bytes();
    let mut begin = marker;
    while begin > 0 && matches!(bytes[begin - 1], b' ' | b'\t') {
        begin -= 1;
    }
    let marker_end = text.find(BLOCK_END).expect("应有结束标记") + BLOCK_END.len();
    let end = text[marker_end..]
        .find('\n')
        .map(|i| marker_end + i + 1)
        .unwrap_or(text.len());
    (text[..begin].to_string(), text[end..].to_string())
}

fn assert_outside_unchanged(label: &str, before: &str, after: &str) {
    let (pre_before, suf_before) = outside(before);
    let (pre_after, suf_after) = outside(after);
    assert_eq!(pre_after, pre_before, "{label}: 块**前**的字节被改动了");
    assert_eq!(suf_after, suf_before, "{label}: 块**后**的字节被改动了");
    // 第二层：sha256 相等（留档用；相等性本身已由上面的逐字节断言保证）
    assert_eq!(
        sha256_hex(pre_after.as_bytes()),
        sha256_hex(pre_before.as_bytes()),
        "{label}: 前缀 sha256 不一致"
    );
    assert_eq!(
        sha256_hex(suf_after.as_bytes()),
        sha256_hex(suf_before.as_bytes()),
        "{label}: 后缀 sha256 不一致"
    );
}

/// 插入场景的不变量：原文在**插入点之前**的部分必须是 `after` 的前缀，
/// 插入点之后的部分必须是 `after` 的后缀（插入点 = `models:` 那一行的行尾）。
fn assert_insertion_preserved(label: &str, original: &str, after: &str) {
    // 插入点 = `models:` 那一行的行尾
    let mut split = 0usize;
    for line in original.split_inclusive('\n') {
        split += line.len();
        if line.trim_start().starts_with("models") && line.contains(':') {
            break;
        }
    }
    let (head, tail) = original.split_at(split);
    assert!(after.starts_with(head), "{label}: 插入点之前的字节变了");
    assert!(after.ends_with(tail), "{label}: 插入点之后的字节变了");
    assert_eq!(
        sha256_hex(head.as_bytes()),
        sha256_hex(&after.as_bytes()[..head.len()]),
        "{label}: 前缀 sha256 不一致"
    );
    assert_eq!(
        sha256_hex(tail.as_bytes()),
        sha256_hex(&after.as_bytes()[after.len() - tail.len()..]),
        "{label}: 后缀 sha256 不一致"
    );
}

// ============================================================ 新建

/// 新建文件的逐字节产物。
///
/// 两处与 M7-S3 spec §5.3 原文不同，都是**用 Continue 自己的解析器实测**后订正的
/// （`@continuedev/config-yaml` 1.42.0 的 `parseConfigYaml`）：
/// - 顶层 `name` / `version` 是必填：缺了报 `name: Required, version: Required`，整份配置拒绝加载；
/// - 条目的 `model` 是必填：缺了报 `models.0: Invalid input`，用户原有的模型也跟着失效。
#[test]
fn creates_the_file_with_the_documented_bytes() {
    let dir = tmp();
    let plan = resolve_for_binding(
        DeliveryChannel::Continue,
        dir.path(),
        BASE,
        OpenCodeWriter::DEFAULT_PROVIDER_ID,
        Some(MODEL),
    )
    .unwrap();
    assert_eq!(
        plan.target_path(),
        dir.path().join(".continue").join("config.yaml")
    );

    let patch = plan.plan(SECRET).unwrap();
    assert_eq!(patch.before, "");
    let expected = "name: \"KeyRelay\"\nversion: \"1.0.0\"\nmodels:\n  # >>> keyrelay managed >>>\n  # 由 KeyRelay 管理；手工修改会在下次投递时被覆盖\n  - name: \"keyrelay\"\n    provider: \"openai\"\n    model: \"gpt-4o\"\n    apiBase: \"https://relay.example.com/v1\"\n    apiKey: \"sk-continue-INT-0123456789abcdef\"\n  # <<< keyrelay managed <<<\n";
    assert_eq!(patch.after, expected, "新建内容必须逐字相等");
    assert_eq!(patch.new_file_mode, Some(0o600));
}

/// 没有模型名就**拒绝写入**：写出一个缺 `model` 的条目会让 Continue 拒绝加载整份配置，
/// 比不投递更糟；而 KeyRelay 不编造默认模型（M7-S0 章程 §4.2 点 4）。
#[test]
fn refuses_to_write_an_entry_without_a_model() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();

    // ① 新建：没有任何地方能取到模型名
    let err = writer(dir.path(), BASE, None).plan(SECRET).unwrap_err();
    assert!(matches!(err, Error::Inject { .. }), "{err:?}");
    assert!(err.to_string().contains("模型名"), "{err}");
    // 纯空白 model 与「没给」等价
    let err = writer(dir.path(), BASE, Some("   "))
        .plan(SECRET)
        .unwrap_err();
    assert!(err.to_string().contains("模型名"), "{err}");

    // ② 已有 `models:`、还没有受管块：同样拒绝，且磁盘零改动
    let before =
        "name: mine\nversion: 1.0.0\nmodels:\n  - name: mine\n    provider: openai\n    model: x\n";
    fs::write(&path, before).unwrap();
    let err = writer(dir.path(), BASE, None).plan(SECRET).unwrap_err();
    assert!(err.to_string().contains("模型名"), "{err}");
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        before,
        "拒绝时磁盘零改动"
    );
}

/// 重投 / 轮换（第②步走的是不带模型名的 `apply_delivery`）沿用**块里已有的**模型名。
#[test]
fn redelivery_without_a_model_keeps_the_one_already_in_the_block() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    let first = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    fs::write(&path, &first.after).unwrap();

    let rotated = writer(dir.path(), BASE, None).plan(ROTATED).unwrap();
    assert!(rotated.after.contains(ROTATED));
    assert!(
        rotated.after.contains("    model: \"gpt-4o\"\n"),
        "{}",
        rotated.after
    );
    assert_outside_unchanged("沿用块内模型名", &first.after, &rotated.after);

    // 显式给了新的模型名 ⇒ 以新的为准
    let switched = writer(dir.path(), BASE, Some("claude-sonnet"))
        .plan(SECRET)
        .unwrap();
    assert!(switched.after.contains("    model: \"claude-sonnet\"\n"));
    assert!(!switched.after.contains("gpt-4o"), "{}", switched.after);
}

/// 块内模型名是本模块自己用双引号渲染的：带引号 / 反斜杠的值必须原样取回（`quote` 的逆）。
#[test]
fn model_with_escapes_round_trips_through_the_block() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();
    // `quote` 会产生的每一种转义都要往返：`\"` `\\` `\t` `\n` `\r`，以及结尾的反斜杠
    let model = "org/\"quoted\" \\ name\ttab\nline\rcr trailing\\";
    let first = writer(dir.path(), BASE, Some(model)).plan(SECRET).unwrap();
    fs::write(&path, &first.after).unwrap();

    let again = writer(dir.path(), BASE, None).plan(SECRET).unwrap();
    assert_eq!(again.after, first.after, "沿用的模型名必须逐字相同");
}

/// 块里的 `model:` 被手工改成 `quote` 产生不了的写法 ⇒ 不猜，拒绝并要求填写模型名；
/// 文件不动（独立复审 P3-2：「拒绝未转义引号」原先没有用例守护）。
#[test]
fn hand_edited_model_that_quote_cannot_produce_is_not_guessed() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();
    let first = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    let rendered = format!("model: \"{MODEL}\"");
    assert!(first.after.contains(&rendered), "{}", first.after);

    for hand_edited in [
        "model: \"a\"b\"",   // 未转义的引号
        "model: 'single'",   // 单引号
        "model: bare",       // 裸值
        "model: \"bad\\q\"", // quote 不会产生的转义
        "model: \"\"",       // 空
    ] {
        let before = first.after.replace(&rendered, hand_edited);
        fs::write(&path, &before).unwrap();
        let err = writer(dir.path(), BASE, None).plan(SECRET).unwrap_err();
        assert!(err.to_string().contains("模型名"), "{hand_edited}: {err}");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            before,
            "拒绝时不得改动文件"
        );
    }
}

// ============================================================ 插入 / 替换

/// `models:` 之后的所有 `- ` 列表项必须**同一缩进**——这是 YAML 块序列的硬要求，
/// 也是「产物仍然可解析」的无依赖判据（PyYAML 实测见 `docs/reviews/M7-S3-复审-探针留档.md`）。
fn assert_uniform_sequence_indent(text: &str) {
    let indents: Vec<&str> = text
        .lines()
        .filter(|line| line.trim_start().starts_with("- "))
        .map(|line| &line[..line.len() - line.trim_start().len()])
        .collect();
    assert!(indents.len() >= 2, "夹具应有多个列表项: {indents:?}");
    assert!(
        indents.iter().all(|i| *i == indents[0]),
        "同一个序列里出现了两种缩进（非法 YAML）: {indents:?}"
    );
}

#[test]
fn zero_indent_list_keeps_zero_indent_and_a_uniform_sequence() {
    // **M7-S3 复审 P1-1 的回归**：YAML 允许块序列项与父键**同缩进**（`models:` 下一行直接是 `- x`）。
    // 旧实现要求「缩进 > 0」才沿用，于是给这种文件塞了 2 空格的条目 ⇒ 序列内两种缩进 ⇒
    // 原文 `safe_load` 通过、投递之后 `ParserError: expected <block end>, but found '-'`。
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    let before = "name: cfg\nmodels:\n- name: \"mine\"\n- name: \"second\"\n";
    fs::write(&path, before).unwrap();

    let patch = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();

    // 块内行首缩进为**空**（与既有条目同缩进）；字段相对条目再缩进两格
    let expected = format!(
        "name: cfg\nmodels:\n{BLOCK_BEGIN}\n# 由 KeyRelay 管理；手工修改会在下次投递时被覆盖\n\
         - name: \"keyrelay\"\n  provider: \"openai\"\n  model: \"{MODEL}\"\n  apiBase: \"{BASE}\"\n  apiKey: \"{SECRET}\"\n{BLOCK_END}\n\
         - name: \"mine\"\n- name: \"second\"\n"
    );
    assert_eq!(patch.after, expected, "0 缩进的产物必须逐字如此");

    assert_uniform_sequence_indent(&patch.after);
    assert_insertion_preserved("0 缩进插入", before, &patch.after);

    // 幂等：二次投递不得产生额外改动
    fs::write(&path, &patch.after).unwrap();
    let second = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    assert_eq!(second.after, patch.after);
}

#[test]
fn inserts_after_the_existing_models_key() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    let before = "name: my-config\nversion: 0.0.1\nmodels:\n  - name: mine\n    provider: openai\n";
    fs::write(&path, before).unwrap();

    let patch = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    assert!(
        patch
            .after
            .starts_with("name: my-config\nversion: 0.0.1\nmodels:\n  # >>>"),
        "{}",
        patch.after
    );
    assert!(
        patch
            .after
            .contains("  - name: mine\n    provider: openai\n"),
        "用户自己的条目必须原样保留: {}",
        patch.after
    );
    assert_eq!(patch.after.matches("models:").count(), 1);
    assert_insertion_preserved("插入", before, &patch.after);
}

#[test]
fn appends_models_when_the_file_has_none() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    let before = "name: my-config"; // 刻意不以换行结尾
    fs::write(&path, before).unwrap();

    let patch = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    assert!(patch.after.starts_with(before), "{}", patch.after);
    assert!(
        patch.after.contains("\nmodels:\n  # >>>"),
        "{}",
        patch.after
    );
    assert!(patch.after.ends_with("  # <<< keyrelay managed <<<\n"));
}

#[test]
fn replaces_the_block_in_place() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    let first = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    fs::write(&path, &first.after).unwrap();

    let rotated = writer(dir.path(), BASE, Some(MODEL)).plan(ROTATED).unwrap();
    assert!(rotated.after.contains(ROTATED));
    assert!(!rotated.after.contains(SECRET), "旧密钥必须被替换掉");
    assert_eq!(rotated.after.matches(BLOCK_BEGIN).count(), 1);
    assert_eq!(rotated.after.matches(BLOCK_END).count(), 1);
    assert_outside_unchanged("原地替换", &first.after, &rotated.after);
}

#[test]
fn is_idempotent() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    let first = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    fs::write(&path, &first.after).unwrap();

    let second = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    assert_eq!(second.before, first.after);
    assert_eq!(second.after, first.after, "二次投递不得产生额外改动");
}

// ============================================================ 块外字节不变（核心断言）

#[test]
fn outside_the_block_is_byte_identical_with_hostile_surroundings() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();

    // 夹具：块前有中文注释 + emoji + 用户的条目；块后有不以换行结尾的尾巴
    let head = "# 我的配置 🚀\nname: \"my config\"\nmodels:\n  # 下面这条是给我自己用的\n  - name: \"mine\"\n    provider: openai\n";
    let tail = "  - name: \"second\"\n    provider: anthropic\n# 没有尾随换行";
    let with_block = format!(
        "{head}  {BLOCK_BEGIN}\n  - name: \"keyrelay\"\n    apiKey: \"sk-old\"\n  {BLOCK_END}\n{tail}"
    );
    fs::write(&path, &with_block).unwrap();

    let patch = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    assert_outside_unchanged("敌意环境（替换）", &with_block, &patch.after);
    assert!(patch.after.ends_with("# 没有尾随换行"), "{}", patch.after);
    assert!(patch.after.contains("# 我的配置 🚀\n"), "{}", patch.after);
    assert!(
        patch.after.contains("# 下面这条是给我自己用的\n"),
        "{}",
        patch.after
    );
}

#[test]
fn outside_the_block_is_byte_identical_when_inserting() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    let before = "# 头注释\nmodels:\n  - name: \"mine\"\n    provider: openai\n# 尾注释（无换行）";
    fs::write(&path, before).unwrap();

    let patch = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    let (pre, suf) = outside(&patch.after);
    assert_eq!(pre, "# 头注释\nmodels:\n", "块前必须逐字节相同");
    assert_eq!(
        suf,
        "  - name: \"mine\"\n    provider: openai\n# 尾注释（无换行）"
    );
    assert_eq!(sha256_hex(suf.as_bytes()), sha256_hex(suf.as_bytes()));
}

/// `models:` 是最后一行且**没有结尾换行**：开始标记不得粘在 `models:` 同一行。
///
/// 粘上之后 `locate_block` 只认行首标记，下一次投递就认不出这个块 ⇒ 换 key、同 key 重投、
/// 轮换第②步全部报「受管块不完整」——而轮换走到这一步时新 key 已经在站点上建好了。
#[test]
fn models_as_the_last_line_without_newline_stays_redeliverable() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    let before = "name: my-config\nversion: 1.0.0\nmodels:"; // 刻意不以换行结尾
    fs::write(&path, before).unwrap();

    let first = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    assert!(
        first
            .after
            .starts_with(&format!("{before}\n  {BLOCK_BEGIN}\n")),
        "开始标记必须另起一行:\n{}",
        first.after
    );
    fs::write(&path, &first.after).unwrap();

    let second = writer(dir.path(), BASE, Some(MODEL))
        .plan(ROTATED)
        .expect("重投必须认得出上一次写下的块");
    assert!(second.after.contains(ROTATED));
    assert!(!second.after.contains(SECRET), "旧密钥必须被替换掉");
    assert_eq!(second.after.matches(BLOCK_BEGIN).count(), 1);
    assert_outside_unchanged("EOF 无换行后重投", &first.after, &second.after);
}

/// 带 BOM 或带引号的 `models` 键必须被认出来——否则会走「追加」分支，
/// 写出第二个顶层 `models:`（Continue 报 `Map keys must be unique`；
/// PyYAML 则静默以后一个为准，用户自己的模型被覆盖）。
#[test]
fn recognizes_bom_and_quoted_models_keys() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    for models_line in [
        "\u{FEFF}models:",
        "\"models\":",
        "'models':",
        "\"models\" : # 注释",
    ] {
        let before = format!("{models_line}\n  - name: mine\n    provider: openai\n");
        fs::write(&path, &before).unwrap();

        let patch = writer(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap_or_else(|e| panic!("「{models_line}」: {e}"));
        assert!(
            !patch.after.contains("\nmodels:"),
            "「{models_line}」被当成没有 models，追加出了第二个 models 键:\n{}",
            patch.after
        );
        assert!(
            patch
                .after
                .starts_with(&format!("{models_line}\n  {BLOCK_BEGIN}\n")),
            "块必须紧跟既有的 models 行:\n{}",
            patch.after
        );
        assert!(
            patch
                .after
                .ends_with("  - name: mine\n    provider: openai\n"),
            "用户条目必须原样保留:\n{}",
            patch.after
        );
    }
}

// ============================================================ 拒绝面

#[test]
fn refuses_orphan_and_duplicate_blocks_without_touching_the_file() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();
    let cases = [
        format!("models:\n  {BLOCK_BEGIN}\n  - name: x\n"),
        format!("models:\n  - name: x\n  {BLOCK_END}\n"),
        format!("models:\n  {BLOCK_BEGIN}\n  {BLOCK_END}\n  {BLOCK_BEGIN}\n  {BLOCK_END}\n"),
        format!("models:\n  {BLOCK_END}\n  {BLOCK_BEGIN}\n"),
    ];
    for bad in cases {
        fs::write(&path, &bad).unwrap();
        let err = writer(dir.path(), BASE, None).plan(SECRET).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), bad, "拒绝时磁盘零改动");
    }
}

#[test]
fn refuses_duplicate_models_and_flow_style() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();
    for (bad, needle) in [
        ("models:\n  - a\nmodels:\n  - b\n", "顶层 `models:`"),
        ("models: [a, b]\n", "行内值"),
    ] {
        fs::write(&path, bad).unwrap();
        let err = writer(dir.path(), BASE, None).plan(SECRET).unwrap_err();
        assert!(err.to_string().contains(needle), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), bad, "拒绝时磁盘零改动");
    }
}

#[test]
fn refuses_empty_key_and_control_characters() {
    let dir = tmp();
    for bad in ["", "   ", "\n"] {
        let err = writer(dir.path(), BASE, None).plan(bad).unwrap_err();
        assert!(err.to_string().contains("密钥为空"), "{err}");
    }
    for (base, key) in [("https://x/\u{7}", SECRET), (BASE, "sk-a\u{1}b")] {
        let err = writer(dir.path(), base, None).plan(key).unwrap_err();
        assert!(err.to_string().contains("控制字符"), "{err}");
    }
}

#[test]
fn errors_never_echo_the_key() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();
    fs::write(&path, format!("models:\n  {BLOCK_BEGIN}\n")).unwrap();
    let err = writer(dir.path(), BASE, None).plan(SECRET).unwrap_err();
    assert!(!err.to_string().contains(SECRET), "{err}");
    assert!(!err.to_string().contains("0123456789abcdef"), "{err}");
}

// ============================================================ 转义 / 行尾 / 预览

#[test]
fn quotes_and_escapes_values() {
    let dir = tmp();
    let patch = writer(dir.path(), "https://x/a: b #c\"d\\e", Some(MODEL))
        .plan(SECRET)
        .unwrap();
    assert!(
        patch
            .after
            .contains("apiBase: \"https://x/a: b #c\\\"d\\\\e\""),
        "{}",
        patch.after
    );
}

#[test]
fn keeps_the_file_line_ending() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    let before = "models:\r\n  - name: mine\r\n";
    fs::write(&path, before).unwrap();

    let patch = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    assert!(
        patch.after.contains("  # >>> keyrelay managed >>>\r\n"),
        "{:?}",
        patch.after
    );
    assert!(patch
        .after
        .contains("    apiKey: \"sk-continue-INT-0123456789abcdef\"\r\n"));
    assert!(!patch.after.contains("\n\n"), "不得混入 LF 行尾");
    assert_insertion_preserved("CRLF 插入", before, &patch.after);
}

#[test]
fn preview_fields_mask_only_the_key() {
    let dir = tmp();
    let plan = writer(dir.path(), BASE, Some(MODEL));
    assert_eq!(plan.field_names(), vec!["apiKey", "apiBase", "model"]);
    let fields = plan.fields(SECRET);
    assert_eq!(fields[0].key, "apiKey");
    assert_eq!(fields[0].masked, "…cdef");
    assert_eq!(fields[1].masked, BASE);
    assert_eq!(fields[2].masked, MODEL);
    assert!(!format!("{fields:?}").contains(SECRET));
}

#[test]
fn plan_does_not_depend_on_the_process_environment() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, Some(MODEL)).path().to_path_buf();
    fs::write(&path, "models:\n").unwrap();

    let first = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    let saved_home = std::env::var("HOME").ok();
    let saved_override = std::env::var("KEYRELAY_HOME").ok();
    std::env::set_var("HOME", "/tmp/keyrelay-not-this-home");
    std::env::set_var("KEYRELAY_HOME", "/tmp/keyrelay-not-this-home");
    let second = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    match saved_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
    match saved_override {
        Some(value) => std::env::set_var("KEYRELAY_HOME", value),
        None => std::env::remove_var("KEYRELAY_HOME"),
    }

    assert_eq!(first.after, second.after, "计划不得依赖进程环境变量");
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "models:\n",
        "计划阶段不得落盘"
    );
}

// ============================================================ M8-S4 §9-10 / §9-11

/// §10.3 C20：`models: []`（Continue 自己生成的**默认模板**形态）要能投进去。
///
/// 「块外字节不变」在这条上的精确表述（§9-10）：除那一行的 `[]` 这一个 token 被抹掉之外，
/// **其余字节逐字节不变**——注释留在原位。下面把「差异恰好一处」用位置 + 长度逐字钉住。
#[test]
fn empty_flow_models_is_normalised_and_everything_else_is_untouched() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();
    let before = "name: mine\nversion: 1.0.0\nmodels: [] # 我的模型\n";
    fs::write(&path, before).unwrap();

    let plan = writer(dir.path(), BASE, Some(MODEL));
    let patch = plan.plan(SECRET).unwrap();

    let pos = before.find("[]").expect("夹具含 `[]`");
    let block = plan.render_block(SECRET, "  ", "\n");
    let tail_len = before.len() - pos - 2;

    // ① `[]` 之前的字节逐字相同
    assert_eq!(&patch.after[..pos], &before[..pos], "`[]` 之前被动过");
    // ② `[]` 之后到文件末尾（含注释与行尾）逐字相同，整体左移 2 字节
    assert_eq!(
        &patch.after[pos..pos + tail_len],
        &before[pos + 2..],
        "`[]` 之后被动过"
    );
    // ③ 其后只有新插入的块 + 一个行尾
    assert_eq!(&patch.after[pos + tail_len..], format!("{block}\n"));
    // ④ 长度账：-2（`[]`）+ 块 + 1 个行尾
    assert_eq!(patch.after.len(), before.len() - 2 + block.len() + 1);
    // ⑤ 注释与 `models:` 键都还在，且没有写出第二个顶层 `models:`
    assert!(
        patch.after.contains("models:  # 我的模型\n"),
        "{}",
        patch.after
    );
    assert_eq!(patch.after.matches("models:").count(), 1, "{}", patch.after);
    // ⑥ 幂等：再投一次走「原地替换块」的分支，产物逐字相同
    fs::write(&path, &patch.after).unwrap();
    let again = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    assert_eq!(again.after, patch.after, "二次投递必须幂等");
}

/// §10.3 C21：**非空** flow 序列仍然拒绝（N-4：只放开空序列这一种形态）。
#[test]
fn non_empty_flow_models_is_still_refused() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();
    for bad in ["models: [a, b]\n", "models: [\"a\"]\n", "models: []x\n"] {
        fs::write(&path, bad).unwrap();
        let err = writer(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("行内值"), "{text}");
        assert!(
            text.contains("块序列") && text.contains("其它通道"),
            "{text}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), bad, "拒绝时磁盘零改动");
    }
}

/// §10.3 C22（P3-5）：只有注释（+ BOM）的文件按「**已有文件**」处理——
/// 只追加 `models:` 与受管块，用户的注释与 BOM **一个字节不动**（绝不整份重写）。
/// 「真正空」（0 字节 / 纯空白）才用新建模板，那条已在 `creates_the_file_with_the_documented_bytes` 钉住。
#[test]
fn comment_only_file_keeps_every_byte() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();
    for before in [
        "# 我的 Continue 配置\n",
        "\u{FEFF}# 我的 Continue 配置\n",
        "   \n# 只有注释\n",
    ] {
        fs::write(&path, before).unwrap();
        let patch = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
        assert!(
            patch.after.starts_with(before),
            "原字节必须是产物的前缀：{:?}",
            patch.after
        );
        assert!(!patch.after.contains("version:"), "已有文件不得补配置头");
        // 原字节逐字保留（含 BOM）：sha256 两层
        assert_eq!(
            sha256_hex(&patch.after.as_bytes()[..before.len()]),
            sha256_hex(before.as_bytes())
        );
        assert!(patch.after.contains(BLOCK_BEGIN) && patch.after.contains(BLOCK_END));
        fs::remove_file(&path).unwrap();
    }
}

/// §10.3 C23（P3-1）：本次不传 model ⇒ 预览要把**沿用的那个名字**念出来，
/// 且产物里的块仍然写着那个名字（预览与产物用同一个 `block_model`，不分叉）。
#[test]
fn preview_shows_the_inherited_model_name() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();

    let first = writer(dir.path(), BASE, Some(MODEL)).plan(SECRET).unwrap();
    fs::write(&path, &first.after).unwrap();

    let inheriting = writer(dir.path(), BASE, None);
    let fields = inheriting.fields(SECRET);
    assert_eq!(fields.len(), 3, "{fields:?}");
    assert_eq!(fields[2].key, "model");
    assert_eq!(fields[2].masked, format!("沿用：{MODEL}"), "{fields:?}");

    let patch = inheriting.plan(ROTATED).unwrap();
    assert!(patch.after.contains(ROTATED), "轮换必须换密钥");
    assert!(
        patch.after.contains("    model: \"gpt-4o\"\n"),
        "沿用的模型名必须写进块里：{}",
        patch.after
    );
}

/// §10.3 C24：没有名字可沿用 ⇒ 预览给「必须填写」，`plan()` 硬门拒绝（`MODEL_REQUIRED`）。
#[test]
fn missing_model_with_nothing_to_inherit_is_refused() {
    let dir = tmp();
    let path = writer(dir.path(), BASE, None).path().to_path_buf();

    // 空文件：预览提示必填
    let fresh = writer(dir.path(), BASE, None);
    let fields = fresh.fields(SECRET);
    assert_eq!(fields[2].masked, "（首次投递必须填写）", "{fields:?}");
    let err = fresh.plan(SECRET).unwrap_err();
    assert!(err.to_string().contains("模型名"), "{err}");

    // 有受管块、但块里没有 model（手工删掉了）⇒ 同样拒绝
    fs::write(
        &path,
        format!("models:\n  {BLOCK_BEGIN}\n  - name: \"keyrelay\"\n  {BLOCK_END}\n"),
    )
    .unwrap();
    let orphaned = writer(dir.path(), BASE, None);
    assert_eq!(
        orphaned.fields(SECRET)[2].masked,
        "（首次投递必须填写）",
        "块里没有 model 时不该编造一个"
    );
    let err = orphaned.plan(SECRET).unwrap_err();
    assert!(err.to_string().contains("模型名"), "{err}");
}

#[test]
fn target_path_is_the_declared_relative_target() {
    let home = Path::new("/tmp/nobody");
    let plan = resolve_for(DeliveryChannel::Continue, home, BASE).unwrap();
    assert_eq!(
        plan.target_path(),
        home.join(DeliveryChannel::Continue.relative_target())
    );
    assert_eq!(
        plan.target_path(),
        PathBuf::from("/tmp/nobody/.continue/config.yaml")
    );
}
