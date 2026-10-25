//! DeepSeek Harness 桌面端通道：`~/.dsh/.credentials.yaml`（YAML 行级）。
//!
//! 只写 `refs:` 段中的 `KEYRELAY_API_KEY` 行，`records:` 段逐字节不动。
//! 不引入 YAML 解析依赖，用行级操作实现。

use std::path::{Path, PathBuf};

use super::json_text::read_text_or_empty;
use super::{masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

const KEY_NAME: &str = "KEYRELAY_API_KEY";
const REFS_HEADER: &str = "refs:";
const VERSION_HEADER: &str = "version: 1";

/// DSH profile 里引用凭据的字段名（M14-S3 spec §4.3 的实测形态）。
///
/// 凭据名形态：`credentials.yaml` 的 `refs:` 段键名与 profile 里的引用值是
/// **同一个裸名**（`KEYRELAY_API_KEY`），不是 `refs.KEYRELAY_API_KEY`、
/// 不是带 `${}` 的环境变量展开形——spec 只实测了裸名形态，展开形不在
/// 本校验的判定内（见 `api_key_env_references` 的注释）。
pub const REFERENCE_FIELD: &str = "apiKeyEnv";

pub struct DshWriter {
    path: PathBuf,
}

impl DshWriter {
    pub const FIELD_API_KEY: &'static str = "KEYRELAY_API_KEY";

    pub fn new(home: &Path, _base_url: &str) -> Self {
        Self::with_path(home.join(".dsh").join(".credentials.yaml"), _base_url)
    }

    pub fn with_path(path: impl Into<PathBuf>, _base_url: &str) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 本 writer 对应的 DSH profile 引用校验（只读，绝不改写任何 profile 文件）。
    ///
    /// profiles 目录由凭据文件路径反推：凭据在 `<dsh>/.credentials.yaml`，
    /// profiles 就在 `<dsh>/profiles`（`DshWriter::new` 的 home 布局下
    /// `<dsh>` = `home/.dsh`）。`with_path` 的自定义路径同样按
    /// 「凭据文件的父目录 + `profiles`」推导，测试因此可用临时目录复现。
    pub fn reference_check(&self) -> DshReferenceCheck {
        let dsh_dir = self.path.parent().unwrap_or(Path::new(""));
        check_credential_reference_in(&dsh_dir.join("profiles"))
    }
}

impl DeliveryWriter for DshWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::DeepSeekHarness
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        vec![KEY_NAME.to_string()]
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        vec![masked_field(KEY_NAME, api_key)]
    }

    fn plan(&self, api_key: &str) -> Result<Patch> {
        let before = read_text_or_empty(&self.path)?;
        let after = build_after(&before, api_key, &self.path)?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

// ==================================================== P0-3：DSH 凭据引用校验
//
// 半注入的缺口（M14-S3 spec §9 已留档为已知风险，本项把它从“文档注明”
// 变成“投递前硬拦”）：`DshWriter` 只写 `~/.dsh/.credentials.yaml` 的
// `refs:` 段，收了 `base_url` 却不使用——DSH 真正的 endpoint 与 provider
// 配置在用户自己配的 profile 文件里（spec §4.3：
// `~/.dsh/profiles/desktop/cordis.patch.yml` 的 provider 块用
// `apiKeyEnv: TIANSHU_API_KEY` 引用 `refs` 中的 key）。于是“凭据写进去了、
// 却没有任何 profile 引用它”时，用户以为投递成功，DSH 实际仍走旧配置。
//
// 校验语义（写进代码注释，汇报里逐字对应）：
// - 查哪些文件：`~/.dsh/profiles/` 下递归找到的全部 `*.patch.yml`
//   （已排序）。只认 patch 文件这一类：spec 只实测了 `cordis.patch.yml`
//   这一类 provider patch，别的 `*.yml` 是不是 DSH 的 provider 配置
//   未经实测，扫进去会把无关文件的同名字段误算成引用。
//   `desktop` 不享特权——它只是 spec 里的一个 profile 名；多 profile 时
//   **至少一个** patch 文件引用即通过（DSH 当前用哪个 profile 由用户在
//   桌面端切换，投递侧猜不出“当前 profile”，猜一个就可能把用户正在用的
//   另一个 profile 误杀；反过来，任一引用都证明凭据已被接线，
//   剩下的“是不是当前 profile”只能由用户在 DSH 里确认）。
// - “引用”的判定：某 patch 文件里存在一行 `apiKeyEnv:`，其值（去引号、
//   去行尾注释后取首个词）**精确等于**凭据名 `KEYRELAY_API_KEY`。
//   精确等于，不是包含：`KEYRELAY_API_KEY_OLD`、
//   `XKEYRELAY_API_KEY`、`${KEYRELAY_API_KEY}` 都不算——包含判定会把
//   旧凭据 / 别的凭据 / 未经实测的展开语法误算成已接线。注释行不算。
// - 无 profile 文件时：状态是 `NoProfiles`，**同样拒绝**（任务要求“未引用
//   则拒绝”，不得悄悄改成警告放行）。首次使用、尚未建任何 profile 的
//   用户会被这条挡住——这是有意的 fail-closed，UX 边缘见拒绝文案与汇报
//   单列说明；放行口只能是用户在 DSH 里建好引用后重投，不在本校验里开。
// - 只读：本节所有函数只读 profile 文件与目录，绝不创建、改写 profile
//   文件；读失败的文件记入 `unreadable_files`（不算引用），拒绝文案里
//   点名，让权限问题不至于静默漏判。

/// DSH 凭据引用校验的结果（可序列化给预览用，不含任何密钥材料）。
///
/// 线格式为 camelCase（与 Tauri DTO 口径一致）：`credentialName` /
/// `profilesDir` / `checkedFiles` / `referencingFiles` / `unreadableFiles`，
/// 路径序列化为字符串。
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DshReferenceCheck {
    /// 凭据名，恒为 `KEYRELAY_API_KEY`。
    pub credential_name: &'static str,
    /// 扫描过的 profiles 目录（即使它不存在，也记下来供文案指路）。
    pub profiles_dir: PathBuf,
    /// 扫描到的全部 patch 文件（已排序；目录不存在或无 patch 文件时为空）。
    pub checked_files: Vec<PathBuf>,
    /// 其中引用了该凭据的文件（为空 ⇔ 未引用）。
    pub referencing_files: Vec<PathBuf>,
    /// 存在但读失败的文件（不算引用；拒绝文案里点名）。
    pub unreadable_files: Vec<PathBuf>,
}

impl DshReferenceCheck {
    /// 是否已有至少一个 profile 引用该凭据。
    pub fn is_referenced(&self) -> bool {
        !self.referencing_files.is_empty()
    }

    /// 是否一个 profile patch 文件都没找到（与“找到了但都没引用”区分：
    /// 前者用户要先建 profile / 补文件，后者只要在已有文件里补一行）。
    pub fn has_no_profiles(&self) -> bool {
        self.checked_files.is_empty()
    }
}

/// `home` 下的 DSH profiles 目录。
pub fn profiles_dir(home: &Path) -> PathBuf {
    home.join(".dsh").join("profiles")
}

/// 递归收集 `profiles_dir` 下的全部 `*.patch.yml`（已排序）。
///
/// 目录不存在、不可读时返回空（不报错）：调用方用 `checked_files.is_empty()`
/// 区分“无 profile”与“有 profile 未引用”，读失败的单文件则在
/// `check_credential_reference_in` 里另记一笔，不在这里吞掉。
fn profile_patch_files(profiles_dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![profiles_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".patch.yml"))
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// 一行文本是否以 `apiKeyEnv: <凭据名>` 的形态引用该凭据。
///
/// 行级判定（不引入 YAML 解析依赖，与本文件行级写盘同口径）：
/// - 注释行（行首 `#`）不算；键必须是 `apiKeyEnv`（`apiKey`、`api_key`
///   等近似键不算——spec 的字段名就是 `apiKeyEnv`）；
/// - 值取冒号后去空白的部分：带引号取引号内原文，不带引号取首个空白前
///   的词（于是行尾 `# 注释` 不影响判定），再与凭据名**精确相等**才算；
/// - `${KEYRELAY_API_KEY}`、`$KEYRELAY_API_KEY` 等展开形不算：spec 只实测
///   了裸名形态，展开形是不是 DSH 认的引用语法未经实测，算进去等于
///   用猜测放行一次半注入。
pub fn api_key_env_references(line: &str, credential_name: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return false;
    }
    let Some(colon) = trimmed.find(':') else {
        return false;
    };
    if trimmed[..colon].trim() != REFERENCE_FIELD {
        return false;
    }
    let value = trimmed[colon + 1..].trim();
    if value.is_empty() {
        return false;
    }
    let first = value.as_bytes()[0];
    if first == b'"' || first == b'\'' {
        let quote = first as char;
        let Some(end) = value[1..].find(quote) else {
            return false;
        };
        return &value[1..1 + end] == credential_name;
    }
    let word = value.split_whitespace().next().unwrap_or("");
    word == credential_name
}

/// 对 `home` 做 DSH 凭据引用校验（只读）。
pub fn check_credential_reference(home: &Path) -> DshReferenceCheck {
    check_credential_reference_in(&profiles_dir(home))
}

/// 对给定的 profiles 目录做校验（`DshWriter::reference_check` 与测试的入口）。
pub fn check_credential_reference_in(profiles_dir: &Path) -> DshReferenceCheck {
    let checked_files = profile_patch_files(profiles_dir);
    let mut referencing_files: Vec<PathBuf> = Vec::new();
    let mut unreadable_files: Vec<PathBuf> = Vec::new();
    for path in &checked_files {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                if text
                    .lines()
                    .any(|line| api_key_env_references(line, KEY_NAME))
                {
                    referencing_files.push(path.clone());
                }
            }
            Err(_) => unreadable_files.push(path.clone()),
        }
    }
    DshReferenceCheck {
        credential_name: KEY_NAME,
        profiles_dir: profiles_dir.to_path_buf(),
        checked_files,
        referencing_files,
        unreadable_files,
    }
}

/// 未引用时的整单拒绝错误（`Error::Inject`：Display 自带目标路径）。
///
/// 文案必须同时带四样，缺一样调用方就得再拼一次：通道名、凭据名、
/// 查过的 profile 文件路径（无文件时改带扫描过的 profiles 目录）、
/// 应补引用的位置与字段。无 profile 与有 profile 未引用的去向不同，
/// 故文案分两支，不共用一句笼统的“引用校验失败”。
pub fn unreferenced_error(check: &DshReferenceCheck, target: &Path) -> Error {
    let mut reason = format!(
        "通道 dsh 投递被拒绝：凭据 {} 未被任何 DSH profile 引用；只写进 {} 的 refs 段不会让 DSH 使用它",
        check.credential_name,
        target.display()
    );
    if check.has_no_profiles() {
        reason.push_str(&format!(
            "；未找到任何 profile patch 文件（已扫描目录：{}，该目录不存在或其中无 *.patch.yml）。请先在 DSH 里建好 profile，并在其 provider 块里补上 {}: {}（例如 {} 的 provider 块，你的 profile 名以实际为准），再重新投递",
            check.profiles_dir.display(),
            REFERENCE_FIELD,
            check.credential_name,
            check.profiles_dir.join("desktop").join("cordis.patch.yml").display()
        ));
    } else {
        let files = check
            .checked_files
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("、");
        reason.push_str(&format!(
            "；已查 profile patch 文件：{files}，其中没有任何一处 {}: {}。请在其中一个文件的 provider 块里补上 {}: {}（例如 {} 的 provider 块），再重新投递",
            REFERENCE_FIELD,
            check.credential_name,
            REFERENCE_FIELD,
            check.credential_name,
            check.checked_files[0].display()
        ));
    }
    if !check.unreadable_files.is_empty() {
        let unreadable = check
            .unreadable_files
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("、");
        reason.push_str(&format!(
            "；以下文件存在但无法读取，未计入引用判定：{unreadable}"
        ));
    }
    reason.push_str("；该单已拒绝，未写入任何内容");
    Error::inject(target, reason)
}

fn build_after(before: &str, api_key: &str, path: &Path) -> Result<String> {
    if api_key.trim().is_empty() {
        return Err(Error::inject(path, "密钥为空，拒绝写入"));
    }

    let target_line = format!("  {KEY_NAME}: {api_key}");

    // 找到 refs: 段的起始行
    if let Some(refs_idx) = find_line_starting_with(before, REFS_HEADER) {
        let before_refs = &before[..refs_idx];
        let after_header = &before[refs_idx..];
        // 跳过 `refs:` 这一行
        let newline_after_header = after_header
            .find('\n')
            .map(|p| p + 1)
            .unwrap_or(after_header.len());
        let refs_body = &after_header[newline_after_header..];

        // 在 refs_body 里找 KEYRELAY_API_KEY 行
        if let Some(key_pos) = find_ref_line(refs_body, KEY_NAME) {
            // 替换这一行
            let line_end = refs_body[key_pos..]
                .find('\n')
                .map(|p| key_pos + p)
                .unwrap_or(refs_body.len());
            let before_key = &refs_body[..key_pos];
            let after_key = &refs_body[line_end..];
            let mut result = String::with_capacity(
                before_refs.len()
                    + newline_after_header
                    + before_key.len()
                    + target_line.len()
                    + after_key.len(),
            );
            result.push_str(before_refs);
            result.push_str(&after_header[..newline_after_header]);
            result.push_str(before_key);
            result.push_str(&target_line);
            result.push_str(after_key);
            Ok(result)
        } else {
            // 在 refs 段末尾追加
            let mut result = String::with_capacity(
                before_refs.len() + newline_after_header + refs_body.len() + target_line.len() + 1,
            );
            result.push_str(before_refs);
            result.push_str(&after_header[..newline_after_header]);
            result.push_str(refs_body);
            if !refs_body.is_empty() && !refs_body.ends_with('\n') {
                result.push('\n');
            }
            result.push_str(&target_line);
            result.push('\n');
            Ok(result)
        }
    } else {
        // refs: 段不存在，追加到文件末尾
        let mut result = String::with_capacity(before.len() + target_line.len() + 20);
        result.push_str(before);
        if !before.is_empty() && !before.ends_with('\n') {
            result.push('\n');
        }
        if !before.contains(VERSION_HEADER) {
            result.push_str(VERSION_HEADER);
            result.push('\n');
        }
        result.push_str(REFS_HEADER);
        result.push('\n');
        result.push_str(&target_line);
        result.push('\n');
        Ok(result)
    }
}

/// 找到第一个以指定前缀开头（忽略行首空格）的行的起始偏移。
fn find_line_starting_with(text: &str, prefix: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in text.lines() {
        if line.trim_start().starts_with(prefix) {
            return Some(offset);
        }
        offset += line.len() + 1;
    }
    None
}

/// 在 YAML 段体里找到 `  KEY_NAME:` 行的起始偏移。
fn find_ref_line(body: &str, key_name: &str) -> Option<usize> {
    let pattern = format!("{key_name}:");
    let mut offset = 0usize;
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&pattern) {
            return Some(offset);
        }
        offset += line.len() + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-dsh-0123456789abcdef";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path) -> DshWriter {
        DshWriter::with_path(dir.join(".credentials.yaml"), "")
    }

    #[test]
    fn creates_fresh_file() {
        let dir = tmp();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        assert!(patch.after.contains("version: 1"));
        assert!(patch.after.contains("refs:"));
        assert!(patch.after.contains("KEYRELAY_API_KEY: "));
        assert!(patch.after.contains(SECRET));
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn appends_refs_section_when_missing() {
        let dir = tmp();
        let before =
            "version: 1\nrecords:\n  some-key:\n    kind: grant\n    payload:\n      secret: abc\n";
        std::fs::write(writer_in(dir.path()).path(), before).unwrap();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        assert!(patch.after.contains("records:"));
        assert!(patch.after.contains("kind: grant"));
        assert!(patch.after.contains("refs:"));
        assert!(patch.after.contains("KEYRELAY_API_KEY: "));
        assert!(patch.after.contains(SECRET));
        let records_start = patch.after.find("records:").unwrap();
        let records_end = patch.after.find("refs:").unwrap();
        assert_eq!(
            &patch.after[records_start..records_end],
            "records:\n  some-key:\n    kind: grant\n    payload:\n      secret: abc\n"
        );
    }

    #[test]
    fn appends_key_to_existing_refs() {
        let dir = tmp();
        let before = "version: 1\nrefs:\n  TIANSHU_API_KEY: sk-other\n";
        std::fs::write(writer_in(dir.path()).path(), before).unwrap();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        assert!(patch.after.contains("TIANSHU_API_KEY: sk-other"));
        assert!(patch.after.contains("KEYRELAY_API_KEY: "));
        assert!(patch.after.contains(SECRET));
    }

    #[test]
    fn replaces_existing_key() {
        let dir = tmp();
        let before = "version: 1\nrefs:\n  KEYRELAY_API_KEY: sk-old\n  TIANSHU_API_KEY: sk-keep\n";
        std::fs::write(writer_in(dir.path()).path(), before).unwrap();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        assert!(!patch.after.contains("sk-old"));
        assert!(patch.after.contains(SECRET));
        assert!(patch.after.contains("TIANSHU_API_KEY: sk-keep"));
    }

    #[test]
    fn records_section_byte_for_byte_preserved() {
        let dir = tmp();
        let records = "version: 1\nrecords:\n  client-connection/browser-session:\n    kind: grant\n    payload:\n      secret: BASE64DATA\n";
        std::fs::write(writer_in(dir.path()).path(), records).unwrap();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        let records_end = patch.after.find("refs:").unwrap();
        assert_eq!(&patch.after[..records_end], records);
    }

    #[test]
    fn rejects_empty_key() {
        let dir = tmp();
        assert!(matches!(
            writer_in(dir.path()).plan(""),
            Err(Error::Inject { .. })
        ));
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        let first = writer_in(dir.path()).plan(SECRET).unwrap();
        std::fs::write(writer_in(dir.path()).path(), &first.after).unwrap();
        let second = writer_in(dir.path()).plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        let err = writer_in(dir.path()).plan("").unwrap_err();
        assert!(!err.to_string().contains("SECRET"), "{err}");
    }

    // ---- P0-3：凭据引用校验 ----

    fn write_profile(dir: &Path, profile: &str, content: &str) -> PathBuf {
        let path = dir.join("profiles").join(profile).join("cordis.patch.yml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn reference_matcher_exact_only() {
        assert!(api_key_env_references(
            "  apiKeyEnv: KEYRELAY_API_KEY",
            KEY_NAME
        ));
        assert!(api_key_env_references(
            "apiKeyEnv: \"KEYRELAY_API_KEY\"",
            KEY_NAME
        ));
        assert!(api_key_env_references(
            "apiKeyEnv: KEYRELAY_API_KEY # 旧注释",
            KEY_NAME
        ));
        assert!(!api_key_env_references(
            "# apiKeyEnv: KEYRELAY_API_KEY",
            KEY_NAME
        ));
        assert!(!api_key_env_references(
            "apiKeyEnv: KEYRELAY_API_KEY_OLD",
            KEY_NAME
        ));
        assert!(!api_key_env_references(
            "apiKeyEnv: ${KEYRELAY_API_KEY}",
            KEY_NAME
        ));
        assert!(!api_key_env_references(
            "apiKey: KEYRELAY_API_KEY",
            KEY_NAME
        ));
        assert!(!api_key_env_references(
            "apiKeyEnv: TIANSHU_API_KEY",
            KEY_NAME
        ));
    }

    #[test]
    fn reference_check_referenced() {
        let dir = tmp();
        let profile = write_profile(
            dir.path(),
            "desktop",
            "providers:\n  keyrelay:\n    apiKeyEnv: KEYRELAY_API_KEY\n    baseURL: https://x\n",
        );
        let check = writer_in(dir.path()).reference_check();
        assert!(check.is_referenced());
        assert!(!check.has_no_profiles());
        assert_eq!(check.referencing_files, vec![profile]);
        assert_eq!(check.credential_name, KEY_NAME);
    }

    #[test]
    fn reference_check_unreferenced() {
        let dir = tmp();
        let profile = write_profile(
            dir.path(),
            "desktop",
            "providers:\n  keyrelay:\n    apiKeyEnv: TIANSHU_API_KEY\n",
        );
        let check = writer_in(dir.path()).reference_check();
        assert!(!check.is_referenced());
        assert!(!check.has_no_profiles());
        assert_eq!(check.checked_files, vec![profile]);
        assert!(check.referencing_files.is_empty());
        let err = unreferenced_error(&check, writer_in(dir.path()).path()).to_string();
        assert!(err.contains("dsh"), "{err}");
        assert!(err.contains("KEYRELAY_API_KEY"), "{err}");
        assert!(err.contains("cordis.patch.yml"), "{err}");
        assert!(err.contains("apiKeyEnv"), "{err}");
    }

    #[test]
    fn reference_check_no_profiles() {
        let dir = tmp();
        let check = writer_in(dir.path()).reference_check();
        assert!(!check.is_referenced());
        assert!(check.has_no_profiles());
        assert!(check.checked_files.is_empty());
        let err = unreferenced_error(&check, writer_in(dir.path()).path()).to_string();
        assert!(err.contains("未找到任何 profile patch 文件"), "{err}");
        assert!(err.contains("profiles"), "{err}");
        assert!(err.contains("desktop"), "{err}");
        assert!(err.contains("apiKeyEnv: KEYRELAY_API_KEY"), "{err}");
    }

    #[test]
    fn reference_check_multi_profile_any_one_passes() {
        let dir = tmp();
        write_profile(dir.path(), "desktop", "apiKeyEnv: TIANSHU_API_KEY\n");
        write_profile(dir.path(), "work", "apiKeyEnv: KEYRELAY_API_KEY\n");
        let check = writer_in(dir.path()).reference_check();
        assert!(check.is_referenced());
        assert_eq!(check.checked_files.len(), 2);
        assert_eq!(check.referencing_files.len(), 1);
        assert!(check.referencing_files[0]
            .display()
            .to_string()
            .contains("work"));
    }

    #[test]
    fn reference_check_ignores_non_patch_files() {
        let dir = tmp();
        let other = dir
            .path()
            .join("profiles")
            .join("desktop")
            .join("other.yml");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::write(&other, "apiKeyEnv: KEYRELAY_API_KEY\n").unwrap();
        let check = writer_in(dir.path()).reference_check();
        assert!(!check.is_referenced());
        assert!(check.checked_files.is_empty());
    }
}
