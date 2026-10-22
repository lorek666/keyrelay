//! 平台相关的路径解析。
//!
//! 存在的理由（BACKLOG B-14）：早先各处直接读 `HOME`，读不到就 `unwrap_or(".")`——
//! 在 Windows 上会把配置写到**当前工作目录**（可能是 `C:\Program Files\...`，也可能是只读的），
//! 用户完全找不到自己的密钥去哪了。现在解析不出来就**明确报错**。

use std::path::PathBuf;

use crate::error::{Error, Result};

/// 覆盖主目录的环境变量。测试与便携部署用，优先级最高。
pub const HOME_OVERRIDE_ENV: &str = "TIANSHU_RELAY_HOME";
/// 旧版覆盖变量（M35-S1 §4.4 兼容）：新变量未设置时回退到它。
pub const LEGACY_HOME_OVERRIDE_ENV: &str = "KEYRELAY_HOME";

/// 用户主目录。
pub fn home_dir() -> Result<PathBuf> {
    home_dir_with(|name| std::env::var(name).ok())
}

/// 与 [`home_dir`] 相同，但环境变量的读取由调用方注入，便于测试各平台分支。
///
/// 分支顺序：
/// 1. `TIANSHU_RELAY_HOME`（显式覆盖，所有平台）
/// 2. `USERPROFILE`（Windows）
/// 3. `HOMEDRIVE` + `HOMEPATH`（Windows，老式配置）
/// 4. `HOME`（macOS / Linux）
pub fn home_dir_with(get: impl Fn(&str) -> Option<String>) -> Result<PathBuf> {
    // 新变量优先；未设置时回退旧变量（兼容旧脚本/旧快捷方式）。
    // 两者都设置时以新变量为准（spec §4.4）。
    let override_value =
        non_empty(get(HOME_OVERRIDE_ENV)).or_else(|| non_empty(get(LEGACY_HOME_OVERRIDE_ENV)));
    if let Some(value) = override_value {
        // 覆盖值必须是**绝对路径**（复审 P2-3）：相对路径会随进程 CWD 漂移，
        // 「密钥到底写到了哪儿」就变成不可预测的事——而这正是本产品最不能含糊的地方。
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(Error::Store(format!(
                "{HOME_OVERRIDE_ENV}（或旧变量 {LEGACY_HOME_OVERRIDE_ENV}）必须是绝对路径，收到的是「{}」。\
                 相对路径会随进程工作目录变化，拒绝使用。",
                path.display()
            )));
        }
        return Ok(path);
    }

    if let Some(value) = non_empty(get("USERPROFILE")) {
        return Ok(PathBuf::from(value));
    }

    // Windows 的老式组合：HOMEDRIVE=C: + HOMEPATH=\Users\me
    if let (Some(drive), Some(path)) = (non_empty(get("HOMEDRIVE")), non_empty(get("HOMEPATH"))) {
        return Ok(PathBuf::from(format!("{drive}{path}")));
    }

    if let Some(value) = non_empty(get("HOME")) {
        return Ok(PathBuf::from(value));
    }

    Err(Error::Store(format!(
        "无法确定用户主目录：{} / USERPROFILE / HOMEDRIVE+HOMEPATH / HOME 都没有可用取值。\
         可以显式设置 {HOME_OVERRIDE_ENV} 指定一个目录。",
        HOME_OVERRIDE_ENV
    )))
}

/// 空串与**纯空白**都算「没有设置」；取值本身要 `trim`。
///
/// 不 trim 会让 `TIANSHU_RELAY_HOME="  /tmp/x  "` 造出一个名字带空格的目录（复审 P2-2）。
/// 其余三个变量是操作系统给的、形状固定，trim 对它们无害。
fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// 本产品的应用数据目录：`<home>/.tianshu-relay`。
pub fn app_data_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".tianshu-relay"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用一组「环境变量」造一个取值函数。数据是**拥有**的，避免闭包捕获生命周期。
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn override_wins_on_every_platform() {
        let get = env_of(&[
            (HOME_OVERRIDE_ENV, "/tmp/portable"),
            ("HOME", "/home/me"),
            ("USERPROFILE", "C:\\Users\\me"),
        ]);
        assert_eq!(home_dir_with(get).unwrap(), PathBuf::from("/tmp/portable"));
    }

    #[test]
    fn windows_userprofile_is_used_when_home_is_missing() {
        let get = env_of(&[("USERPROFILE", "C:\\Users\\me")]);
        assert_eq!(home_dir_with(get).unwrap(), PathBuf::from("C:\\Users\\me"));
    }

    #[test]
    fn windows_drive_plus_path_is_joined() {
        let get = env_of(&[("HOMEDRIVE", "C:"), ("HOMEPATH", "\\Users\\me")]);
        assert_eq!(home_dir_with(get).unwrap(), PathBuf::from("C:\\Users\\me"));
    }

    #[test]
    fn posix_home_is_used_as_the_last_resort() {
        let get = env_of(&[("HOME", "/home/me")]);
        assert_eq!(home_dir_with(get).unwrap(), PathBuf::from("/home/me"));
    }

    #[test]
    fn empty_values_are_ignored() {
        // 空串/纯空白不能当成有效路径（否则会返回 `PathBuf::from("")`）
        let get = env_of(&[
            (HOME_OVERRIDE_ENV, "   "),
            ("USERPROFILE", ""),
            ("HOME", "/home/me"),
        ]);
        assert_eq!(home_dir_with(get).unwrap(), PathBuf::from("/home/me"));
    }

    #[test]
    fn missing_everything_is_an_error_not_a_dot() {
        // 这是 B-14 的核心：以前会 `unwrap_or(".")`，把配置写到当前工作目录
        let err = home_dir_with(|_| None).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("主目录"), "{message}");
        assert!(
            message.contains(HOME_OVERRIDE_ENV),
            "错误里要告诉用户怎么显式指定: {message}"
        );
    }

    #[test]
    fn all_empty_strings_are_also_an_error() {
        let get = env_of(&[("HOME", ""), ("USERPROFILE", " "), ("HOMEDRIVE", "")]);
        assert!(home_dir_with(get).is_err());
    }

    #[test]
    fn override_is_trimmed() {
        // 复审 P2-2：`"  /tmp/padded  "` 以前会原样变成名字带空格的目录
        let get = env_of(&[(HOME_OVERRIDE_ENV, "  /tmp/padded  ")]);
        assert_eq!(home_dir_with(get).unwrap(), PathBuf::from("/tmp/padded"));
    }

    #[test]
    fn a_relative_override_is_refused() {
        // 复审 P2-3：相对路径随 CWD 漂移，密钥写到哪儿就不可预测了
        let get = env_of(&[(HOME_OVERRIDE_ENV, "relative/dir"), ("HOME", "/home/me")]);
        let err = home_dir_with(get).unwrap_err().to_string();
        assert!(err.contains("绝对路径"), "{err}");
        assert!(err.contains("relative/dir"), "错误里要回显收到的值: {err}");
    }

    #[test]
    fn a_relative_override_does_not_silently_fall_back() {
        // 拒绝，而不是「忽略覆盖值、悄悄用 HOME」——后者会让用户以为覆盖生效了
        let get = env_of(&[(HOME_OVERRIDE_ENV, "./x"), ("HOME", "/home/me")]);
        assert!(home_dir_with(get).is_err());
    }
}
