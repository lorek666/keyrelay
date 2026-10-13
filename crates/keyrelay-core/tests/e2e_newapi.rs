//! 端到端：**真实 `reqwest` + 重试层 + 服务层**，对 `127.0.0.1` 上的假 NewAPI 站点跑完整链路
//! （指纹 → 加密登录 → 列令牌 → 建令牌 → 读明文 → 余额）。
//!
//! 假站点是**有状态**的：它会真的用私钥解密登录密文校验密码、真的记录创建出来的令牌，
//! 因此这条测试同时覆盖了「客户端加密正确」与「服务端契约正确」。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use base64::Engine as _;
use keyrelay_core::service::KeyRelayService;
use keyrelay_core::service::ServiceConfig;
use keyrelay_core::site::retry::{RetryPolicy, RetryingTransport};
use keyrelay_core::site::transport::HttpTransport;
use keyrelay_core::site::transport_reqwest::{ReqwestTransport, TransportConfig};
use keyrelay_core::site::{Credentials, KeySpec};
use keyrelay_core::store::Store;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

const PASSWORD: &str = "hunter2";
const SESSION_COOKIE: &str = "session=e2e-cookie";

#[derive(Default)]
struct SiteState {
    /// 已创建的令牌名（假站点用它生成列表）
    tokens: Vec<String>,
}

struct FakeSite {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let content_length = text[..head_end]
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if buf.len() >= head_end + 4 + content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn respond(stream: &mut TcpStream, status: &str, body: &str, cookie: Option<&str>) {
    let cookie_header = cookie
        .map(|c| format!("Set-Cookie: {c}\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{cookie_header}\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn body_of(raw: &str) -> &str {
    raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

fn spawn_fake_newapi(private: RsaPrivateKey, public_pem: String) -> FakeSite {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取本地地址");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&requests);
    let state = Arc::new(Mutex::new(SiteState::default()));
    let site_state = Arc::clone(&state);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let raw = read_request(&mut stream);
            if let Ok(mut log) = recorder.lock() {
                log.push(raw.clone());
            }

            let first_line = raw.lines().next().unwrap_or_default().to_string();
            let body = body_of(&raw).to_string();

            if first_line.starts_with("GET /api/status") {
                respond(
                    &mut stream,
                    "200 OK",
                    r#"{"success":true,"data":{"version":"v0.9.1","quota_per_unit":500000,"system_name":"假站点"}}"#,
                    None,
                );
            } else if first_line.starts_with("GET /api/user/login/encryption-key") {
                let payload = format!(
                    r#"{{"success":true,"data":{{"enabled":true,"kid":"kid-e2e","public_key":{}}}}}"#,
                    serde_json::to_string(&public_pem).expect("序列化 PEM")
                );
                respond(&mut stream, "200 OK", &payload, None);
            } else if first_line.starts_with("POST /api/user/login") {
                let value: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                let encrypted = value
                    .get("password_encrypted")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let kid = value
                    .get("encryption_key_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                if encrypted.is_empty() || kid != "kid-e2e" {
                    respond(
                        &mut stream,
                        "401 Unauthorized",
                        r#"{"success":false,"message":"missing encrypted password"}"#,
                        None,
                    );
                    continue;
                }

                let Ok(ciphertext) = base64::engine::general_purpose::STANDARD.decode(encrypted)
                else {
                    respond(&mut stream, "400 Bad Request", r#"{"success":false}"#, None);
                    continue;
                };
                match private.decrypt(Oaep::new::<Sha256>(), &ciphertext) {
                    Ok(plaintext) if plaintext == PASSWORD.as_bytes() => respond(
                        &mut stream,
                        "200 OK",
                        r#"{"success":true,"message":"","data":{"id":42,"username":"me"}}"#,
                        Some(SESSION_COOKIE),
                    ),
                    _ => respond(
                        &mut stream,
                        "401 Unauthorized",
                        r#"{"success":false,"message":"wrong password"}"#,
                        None,
                    ),
                }
            } else if first_line.starts_with("GET /api/token/") {
                let items: Vec<String> = site_state
                    .lock()
                    .map(|s| {
                        s.tokens
                            .iter()
                            .enumerate()
                            .map(|(i, name)| {
                                format!(
                                    r#"{{"id":{},"name":"{}","status":1,"created_time":{}}}"#,
                                    i + 1,
                                    name,
                                    1_700_000_000 + i as i64
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let payload = format!(
                    r#"{{"success":true,"data":{{"items":[{}],"total":{}}}}}"#,
                    items.join(","),
                    items.len()
                );
                respond(&mut stream, "200 OK", &payload, None);
            } else if first_line.starts_with("POST /api/token/") && first_line.contains("/key") {
                // 必须排在「创建令牌」分支之前：`POST /api/token/1/key` 也以 `POST /api/token/` 开头
                respond(
                    &mut stream,
                    "200 OK",
                    r#"{"success":true,"data":{"key":"sk-e2e-abcdefgh12345678"}}"#,
                    None,
                );
            } else if first_line.starts_with("POST /api/token/") {
                // 名字从请求体里取（M8-S5B §6.5）：假站点不能只认一个硬编码的名字，
                // 否则「建第二把带分组的 key」这条路径根本走不到。
                // 解析失败时退回流名，绝不静默丢请求。
                let name = serde_json::from_str::<serde_json::Value>(body.as_str())
                    .ok()
                    .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .unwrap_or_else(|| "codex/daily".to_string());
                if let Ok(mut s) = site_state.lock() {
                    s.tokens.push(name);
                }
                respond(
                    &mut stream,
                    "200 OK",
                    r#"{"success":true,"message":""}"#,
                    None,
                );
            } else if first_line.starts_with("GET /api/user/self") {
                respond(
                    &mut stream,
                    "200 OK",
                    r#"{"success":true,"data":{"quota":1000000,"used_quota":500000,"quota_per_unit":500000}}"#,
                    None,
                );
            } else {
                respond(&mut stream, "404 Not Found", r#"{"success":false}"#, None);
            }
        }
    });

    FakeSite {
        base_url: format!("http://{addr}"),
        requests,
    }
}

/// 测试装配：内存钥匙串 + 一次性临时目录（绝不碰真实 `~/.keyrelay`）。
fn test_config() -> ServiceConfig {
    ServiceConfig::in_memory(std::env::temp_dir().join("keyrelay-e2e-home"))
}

#[tokio::test]
async fn full_flow_against_fake_newapi_site() {
    let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("生成站点密钥");
    let public_pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("导出 PEM");
    let site = spawn_fake_newapi(private, public_pem);

    // 用**文件库**而不是内存库：这样测试结束后可以扫描落盘文件，验证密钥/密码不入库
    // （对应验收标准 §8.6；复审 P2-5 指出原实现只用了内存库、无法真正验证）
    let dir = tempfile::tempdir().expect("临时目录");
    let db_path = dir.path().join("e2e.db");
    let store = Store::open(&db_path).expect("文件库");
    let transport = RetryingTransport::new(
        ReqwestTransport::new(TransportConfig::default()).expect("构造真实传输层"),
        RetryPolicy::default(),
    );
    let service = KeyRelayService::new(store, transport, test_config());

    // ① 指纹识别 + 落库
    let summary = service.add_site(&site.base_url).await.expect("识别站点");
    assert_eq!(summary.kind, "newapi");
    assert_eq!(summary.display_name, "假站点");

    // ② 加密登录（假站点会用私钥解密校验）
    service
        .login(summary.id, Credentials::new("me", PASSWORD))
        .await
        .expect("加密登录成功");

    // ③ 列令牌（此时还没有）
    assert!(service
        .list_keys(summary.id)
        .await
        .expect("列令牌")
        .is_empty());

    // ④ 建令牌 → 读明文 → **立刻进钥匙串 + 落库**（服务层不再把明文返回给上层）
    let stored = service
        .create_key(summary.id, KeySpec::named("codex/daily"))
        .await
        .expect("创建令牌");
    assert_eq!(stored.remote_id, "1");
    assert_eq!(stored.name, "codex/daily");
    assert_eq!(stored.masked, "…5678", "只暴露末 4 位");

    // ⑤ 再次列令牌应能看到它
    let keys = service.list_keys(summary.id).await.expect("再列令牌");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].name, "codex/daily");

    // ④-b 分组名必须落库（M8-S5B §6.5）：用户刚填的 `KeySpec.group` 是权威值，
    // 此前 `insert_key` 根本不写 `group_name` ⇒ 本地行这一列恒为 NULL，
    // 界面显示空、按分组筛选失真。上面那把没填分组 ⇒ NULL；这里补一把填了分组的。
    let grouped = service
        .create_key(
            summary.id,
            KeySpec {
                group: Some("vip".to_string()),
                ..KeySpec::named("codex/grouped")
            },
        )
        .await
        .expect("创建带分组的令牌");
    let row = service
        .store()
        .get_key(grouped.id)
        .expect("读本地行")
        .expect("行在");
    assert_eq!(
        row.group_name.as_deref(),
        Some("vip"),
        "分组名必须原样落库（不猜、不改写）"
    );
    // 没填分组的那把必须是 NULL，而不是空串——「不知道」与「空分组」是两件事
    let plain = service
        .store()
        .get_key(stored.id)
        .expect("读本地行")
        .expect("行在");
    assert_eq!(plain.group_name, None, "没填分组 ⇒ NULL");
    // `status` 仍然不写：它是本地词表，`unknown` 的含义是「本产品没对它做过任何事」
    assert_eq!(
        row.status, "unknown",
        "新建时不写站点侧状态（本地词表语义）"
    );

    // ⑥ 余额（quota / quota_per_unit）
    let balance = service.balance(summary.id).await.expect("查余额");
    assert_eq!(balance.remaining, 2.0);
    assert_eq!(balance.used, 1.0);

    // ⑦ 服务端看到的请求序列与关键约束
    let requests = site.requests.lock().unwrap().clone();
    let lines: Vec<String> = requests
        .iter()
        .map(|r| r.lines().next().unwrap_or_default().to_string())
        .collect();

    assert_eq!(lines[0], "GET /api/status HTTP/1.1");
    assert_eq!(lines[1], "GET /api/user/login/encryption-key HTTP/1.1");
    assert_eq!(lines[2], "POST /api/user/login HTTP/1.1");
    assert!(lines.contains(&"POST /api/token/ HTTP/1.1".to_string()));
    assert!(lines.contains(&"POST /api/token/1/key HTTP/1.1".to_string()));
    assert!(lines.contains(&"GET /api/user/self HTTP/1.1".to_string()));

    // 登录请求体必须是密文，绝不出现明文密码
    let login_raw = &requests[2];
    assert!(
        !login_raw.contains(PASSWORD),
        "登录请求不得出现明文密码: {login_raw}"
    );
    assert!(login_raw.contains("password_encrypted"));
    assert!(login_raw.contains("kid-e2e"));

    // 列令牌请求必须带登录 cookie
    let list_raw = requests
        .iter()
        .find(|r| r.starts_with("GET /api/token/"))
        .expect("有列令牌请求");
    assert!(
        list_raw
            .to_lowercase()
            .contains("cookie: session=e2e-cookie"),
        "列表请求缺少会话 cookie: {list_raw}"
    );

    // ⑧ 落盘泄漏扫描（验收标准 §8.6）：库文件与 WAL 里都不得出现密码或密钥明文。
    // 复审 P2-5 指出原实现只用了内存库，无法真正验证这一点。
    for suffix in ["", "-wal", "-shm"] {
        let path = std::path::PathBuf::from(format!("{}{suffix}", db_path.display()));
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(PASSWORD),
            "数据库文件 {} 含明文密码",
            path.display()
        );
        assert!(
            !text.contains("sk-e2e-abcdefgh12345678"),
            "数据库文件 {} 含密钥明文",
            path.display()
        );
    }
}

#[tokio::test]
async fn wrong_password_is_rejected_by_fake_site() {
    let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("生成站点密钥");
    let public_pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("导出 PEM");
    let site = spawn_fake_newapi(private, public_pem);

    let store = Store::open_in_memory().expect("内存库");
    let transport = RetryingTransport::new(
        ReqwestTransport::new(TransportConfig::default()).expect("构造真实传输层"),
        RetryPolicy::default(),
    );
    let service = KeyRelayService::new(store, transport, test_config());

    let summary = service.add_site(&site.base_url).await.expect("识别站点");
    let err = service
        .login(summary.id, Credentials::new("me", "wrong-password"))
        .await
        .expect_err("错误密码必须失败");

    assert!(
        matches!(err, keyrelay_core::Error::AuthFailed(_)),
        "实际: {err:?}"
    );
    // 失败后不得留下会话
    assert!(service.list_keys(summary.id).await.is_err());
}

#[test]
fn real_transport_is_actually_used() {
    // 防呆：确认这条端到端测试用的是真实 reqwest 传输层，而不是 mock
    let transport = ReqwestTransport::new(TransportConfig::default()).expect("构造");
    let debug = format!("{transport:?}");
    assert!(debug.contains("ReqwestTransport"));
    let _ = &transport as &dyn HttpTransport; // 确认实现了传输层契约
}
