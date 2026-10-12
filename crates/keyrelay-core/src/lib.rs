//! KeyRelay 核心库：站点适配器、agent 注入器、钥匙串与本地存储。
//!
//! 设计约束（见 `docs/ADR/0001-技术选型与命名.md`）：
//! - **不依赖 Tauri**：核心逻辑必须能脱离 UI 做单元与契约测试。
//! - **不落明文密钥**：本库任何类型都不得把 `sk-` / `nap-` / PAT 明文写入磁盘、日志或错误信息。

pub mod audit;
pub mod delivery;
pub mod drift;
pub mod error;
pub mod inject;
pub mod observability;
pub mod platform;
pub mod redact;
pub mod service;
pub mod settings;
pub mod site;
pub mod store;
pub mod vault;

pub use error::{Error, Result, SecondFactorKind};
