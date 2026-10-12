//! 平台相关的路径解析。
//!
//! 存在的理由（BACKLOG B-14）：早先各处直接读 `HOME`，读不到就 `unwrap_or(".")`——
//! 在 Windows 上会把配置写到**当前工作目录**（可能是 `C:\Program Files\...`，也可能是只读的），
//! 用户完全找不到自己的密钥去哪了。现在解析不出来就**明确报错**。

use std::path::PathBuf;

use crate::error::{Error, Result};

/// 覆盖主目录的环境变量。测试与便携部署用，优先级最高。
pub const HOME_OVERRIDE_ENV: &str = "KEYRELAY_HOME";

/// 用户主目录。
pub fn home_dir() -> Result<PathBuf> {
    home_dir_with(|name| std::env::var(name).ok())
}

/// 与 [`home_dir`] 相同，但环境变量的读取由调用方注入，便于测试各平台分支。
///
/// 分支顺序：
/// 1. `KEYRELAY_HOME`（显式覆盖，所有平台）
/// 2. `USERPROFILE`（Windows）
/// 3. `HOMEDRIVE` + `HOMEPATH`（Windows，老式配置）
/// 4. `HOME`（macOS / Linux）
pub fn home_dir_with(get: impl Fn(&str) -> Option<String>) -> Result<PathBuf> {
    if let Some(value) = non_empty(get(HOME_OVERRIDE_ENV)) {
        return Ok(PathBuf::from(value));
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

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

/// 本产品的应用数据目录：`<home>/.keyrelay`。
pub fn app_data_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".keyrelay"))
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
}
