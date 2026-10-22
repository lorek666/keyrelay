//! B-49：Sub2API 的**真实栈**端到端（`reqwest` + 重试层 + 服务层）对 `127.0.0.1` 上的假 Sub2API 站点。
//!
//! 与契约测试的区别：这里走真实 TCP，验证「路由拼接、Bearer 头、信封解析、2FA 两段式、
//! 明文剥离」在真实 HTTP 栈上同样成立。
//!
//! 假站点是**有状态**的：它真的校验密码、真的维护令牌表、真的在列表响应里**回传明文密钥**——
//! 因此这条测试同时覆盖了「客户端解析正确」与「服务端明文不外流」两条。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::retry::{RetryPolicy, RetryingTransport};
use tianshu_relay_core::site::transport_reqwest::{ReqwestTransport, TransportConfig};
use tianshu_relay_core::site::SiteKind;
use tianshu_relay_core::site::{Credentials, KeySpec};
use tianshu_relay_core::store::Store;

const PASSWORD: &str = "hunter2";
const TOTP: &str = "123456";
const TOKEN: &str = "sub2api-access-token";
const CREATED_SECRET: &str = "sk-SUB2API-E2E-SECRET-0123456789";
const SEEDED_SECRET: &str = "sk-SUB2API-SEEDED-0123456789";

#[derive(Default)]
struct SiteState {
    /// 已创建的令牌：(id, name, key)
    keys: Vec<(i64, String, String)>,
    next_id: i64,
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

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn body_of(raw: &str) -> &str {
    raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

fn header_of<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    raw.lines().take_while(|l| !l.is_empty()).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn ok(data: serde_json::Value) -> String {
    serde_json::json!({"code": 0, "message": "success", "data": data}).to_string()
}

fn key_json(id: i64, name: &str, key: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id, "user_id": 3, "key": key, "name": name,
        "group_id": 1, "status": "active",
        "created_at": "2026-07-27T05:03:01.628Z", "last_used_at": null,
        "quota": 10.0, "quota_used": 2.5
    })
}

fn spawn_fake_sub2api() -> FakeSite {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取本地地址");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&requests);
    let state = Arc::new(Mutex::new(SiteState {
        keys: vec![(1, "seed/key".to_string(), SEEDED_SECRET.to_string())],
        next_id: 2,
    }));
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
            let auth = header_of(&raw, "authorization").unwrap_or_default();
            let authed = auth == format!("Bearer {TOKEN}");

            // 把「方法」与「不含查询串的路径」拆开：分页参数会让 `starts_with` 判断失准
            let mut parts = first_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let path = parts
                .next()
                .unwrap_or_default()
                .split('?')
                .next()
                .unwrap_or_default()
                .to_string();

            match (method.as_str(), path.as_str()) {
                ("GET", "/api/v1/settings/public") => {
                    respond(
                        &mut stream,
                        "200 OK",
                        &ok(serde_json::json!({
                            "site_name": "假 Sub2API",
                            "api_base_url": "https://sub.example.com",
                            "totp_enabled": true,
                        })),
                    );
                }
                ("POST", "/api/v1/auth/login/2fa") => {
                    let value: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    let token_ok =
                        value.get("temp_token").and_then(|v| v.as_str()) == Some("temp-e2e");
                    let code_ok = value.get("totp_code").and_then(|v| v.as_str()) == Some(TOTP);
                    if token_ok && code_ok {
                        respond(
                            &mut stream,
                            "200 OK",
                            &ok(serde_json::json!({
                                "access_token": TOKEN,
                                "token_type": "Bearer",
                                "user": {"id": 3, "email": "me@example.com"}
                            })),
                        );
                    } else {
                        respond(
                            &mut stream,
                            "401 Unauthorized",
                            &serde_json::json!({"code": 401, "message": "invalid totp code"})
                                .to_string(),
                        );
                    }
                }
                ("POST", "/api/v1/auth/login") => {
                    let value: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    // 字段名必须是 email（不是 username）
                    let email = value.get("email").and_then(|v| v.as_str());
                    let password = value.get("password").and_then(|v| v.as_str());
                    if email == Some("me@example.com") && password == Some(PASSWORD) {
                        // 站点要求二次验证 → 只给 temp_token
                        respond(
                            &mut stream,
                            "200 OK",
                            &ok(serde_json::json!({
                                "requires_2fa": true,
                                "temp_token": "temp-e2e"
                            })),
                        );
                    } else {
                        respond(
                            &mut stream,
                            "401 Unauthorized",
                            &serde_json::json!({"code": 401, "message": "invalid credentials"})
                                .to_string(),
                        );
                    }
                }
                ("GET", "/api/v1/keys") => {
                    if !authed {
                        respond(
                            &mut stream,
                            "401 Unauthorized",
                            &serde_json::json!({"code": 401, "message": "unauthorized"})
                                .to_string(),
                        );
                        continue;
                    }
                    let list: Vec<serde_json::Value> = site_state
                        .lock()
                        .map(|s| {
                            s.keys
                                .iter()
                                .map(|(id, name, key)| key_json(*id, name, key))
                                .collect()
                        })
                        .unwrap_or_default();
                    // **真实形态**：`response.Paginated` → `data = {items, total, ...}`
                    // （复审 P1-1：早先这里返回裸数组，与契约测试同源错误，抓不到真问题）
                    let total = list.len() as i64;
                    respond(
                        &mut stream,
                        "200 OK",
                        &ok(serde_json::json!({
                            "items": list,
                            "total": total,
                            "page": 1,
                            "page_size": 100,
                            "pages": 1
                        })),
                    );
                }
                ("POST", "/api/v1/keys") => {
                    if !authed {
                        respond(
                            &mut stream,
                            "401 Unauthorized",
                            &serde_json::json!({"code": 401, "message": "unauthorized"})
                                .to_string(),
                        );
                        continue;
                    }
                    let value: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    let name = value
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unnamed")
                        .to_string();
                    let id = {
                        let mut s = site_state.lock().expect("锁");
                        let id = s.next_id;
                        s.next_id += 1;
                        s.keys.push((id, name.clone(), CREATED_SECRET.to_string()));
                        id
                    };
                    respond(
                        &mut stream,
                        "201 Created",
                        &ok(key_json(id, &name, CREATED_SECRET)),
                    );
                }
                ("DELETE", p) if p.starts_with("/api/v1/keys/") => {
                    if !authed {
                        respond(
                            &mut stream,
                            "401 Unauthorized",
                            &serde_json::json!({"code": 401, "message": "unauthorized"})
                                .to_string(),
                        );
                        continue;
                    }
                    let id: i64 = path
                        .rsplit('/')
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(-1);
                    if let Ok(mut s) = site_state.lock() {
                        s.keys.retain(|(k, _, _)| *k != id);
                    }
                    respond(&mut stream, "200 OK", &ok(serde_json::Value::Null));
                }
                ("GET", p) if p.starts_with("/api/v1/keys/") => {
                    if !authed {
                        respond(
                            &mut stream,
                            "401 Unauthorized",
                            &serde_json::json!({"code": 401, "message": "unauthorized"})
                                .to_string(),
                        );
                        continue;
                    }
                    let id: i64 = path
                        .rsplit('/')
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(-1);
                    let found = site_state
                        .lock()
                        .ok()
                        .and_then(|s| s.keys.iter().find(|(k, _, _)| *k == id).cloned());
                    match found {
                        Some((id, name, key)) => {
                            respond(&mut stream, "200 OK", &ok(key_json(id, &name, &key)))
                        }
                        None => respond(
                            &mut stream,
                            "404 Not Found",
                            &serde_json::json!({"code": 404, "message": "not found"}).to_string(),
                        ),
                    }
                }
                ("GET", "/api/v1/user/profile") => {
                    if !authed {
                        respond(
                            &mut stream,
                            "401 Unauthorized",
                            &serde_json::json!({"code": 401, "message": "unauthorized"})
                                .to_string(),
                        );
                        continue;
                    }
                    respond(
                        &mut stream,
                        "200 OK",
                        &ok(serde_json::json!({
                            "id": 3, "email": "me@example.com",
                            "balance": 12.5, "total_recharged": 20.0
                        })),
                    );
                }
                _ => respond(
                    &mut stream,
                    "404 Not Found",
                    &serde_json::json!({"code": 404, "message": "unknown route"}).to_string(),
                ),
            }
        }
    });

    FakeSite {
        base_url: format!("http://{addr}"),
        requests,
    }
}

fn build_service(
    dir: &std::path::Path,
    base_url: &str,
) -> TianshuRelayService<RetryingTransport<ReqwestTransport>> {
    let store = Store::open(&dir.join("tianshu-relay.db")).expect("文件库");
    let inner = ReqwestTransport::new(TransportConfig::default()).expect("构造传输层");
    let transport = RetryingTransport::new(inner, RetryPolicy::default());
    let service =
        TianshuRelayService::new(store, transport, ServiceConfig::in_memory(dir.join("home")));
    let _ = base_url;
    service
}

#[tokio::test]
async fn full_flow_against_fake_sub2api_site() {
    let site = spawn_fake_sub2api();
    let dir = tempfile::tempdir().expect("临时目录");
    std::fs::create_dir_all(dir.path().join("home")).unwrap();
    let service = build_service(dir.path(), &site.base_url);

    // ① 指纹识别
    let summary = service.add_site(&site.base_url).await.expect("识别站点");
    assert_eq!(summary.kind, SiteKind::Sub2Api.as_str());
    assert_eq!(summary.display_name, "假 Sub2API");

    // ② 第一次登录：站点要求二次验证
    let err = service
        .login(summary.id, Credentials::new("me@example.com", PASSWORD))
        .await
        .expect_err("应要求二次验证");
    assert!(
        matches!(
            err,
            tianshu_relay_core::Error::SecondFactorRequired {
                kind: tianshu_relay_core::SecondFactorKind::Totp
            }
        ),
        "{err:?}"
    );

    // ③ 带 TOTP 完成登录
    service
        .login(
            summary.id,
            Credentials::new("me@example.com", PASSWORD).with_second_factor(TOTP),
        )
        .await
        .expect("带验证码应登录成功");

    // ④ 列举密钥（**响应里每项都带明文**）
    let keys = service.list_keys(summary.id).await.expect("列举密钥");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].name, "seed/key");
    let debug = format!("{keys:?}");
    assert!(
        !debug.contains(SEEDED_SECRET) && !debug.contains("sk-"),
        "KeyMeta 泄漏明文: {debug}"
    );

    // ⑤ 新建密钥 → 明文立刻进钥匙串 + 落库
    let stored = service
        .create_key(summary.id, KeySpec::named("codex/daily"))
        .await
        .expect("创建密钥");
    assert_eq!(stored.name, "codex/daily");
    assert_eq!(stored.masked, "…6789");
    assert!(!format!("{stored:?}").contains(CREATED_SECRET));

    // ⑥ 读明文（只有显式 reveal 才拿得到）
    let material = service
        .reveal_key(summary.id, &stored.remote_id)
        .await
        .expect("读明文");
    assert_eq!(material.secret, CREATED_SECRET);

    // ⑦ 余额
    let balance = service.balance(summary.id).await.expect("查余额");
    assert_eq!(balance.currency, "USD");
    assert!((balance.remaining - 12.5).abs() < f64::EPSILON);

    // ⑧ 删除
    service
        .revoke_key(summary.id, &stored.remote_id)
        .await
        .expect("删除密钥");
    let keys = service.list_keys(summary.id).await.expect("再列举");
    assert_eq!(keys.len(), 1, "新键应已被删除");

    // ⑨ **红线**：SQLite（含 WAL/SHM）与事件表都不得出现明文
    for suffix in ["", "-wal", "-shm"] {
        let path = dir.path().join(format!("tianshu-relay.db{suffix}"));
        if let Ok(bytes) = std::fs::read(&path) {
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(CREATED_SECRET), "{} 含明文", path.display());
            assert!(!text.contains(SEEDED_SECRET), "{} 含明文", path.display());
        }
    }
    for row in service.recent_events(500).unwrap() {
        assert!(
            !row.message.contains(CREATED_SECRET),
            "事件泄漏: {}",
            row.message
        );
        if let Some(p) = &row.payload {
            assert!(!p.contains(CREATED_SECRET), "事件载荷泄漏: {p}");
        }
    }
    let exported = service.export_diagnostics(200).unwrap();
    assert!(!exported.contains(CREATED_SECRET));
    assert!(!exported.contains(SEEDED_SECRET));

    // ⑩ 请求序列抽查：登录两次（密码 → 2FA），且**没有**把 username 当字段名发出去
    let log = site.requests.lock().expect("锁").clone();
    let login_bodies: Vec<String> = log
        .iter()
        .filter(|r| r.starts_with("POST /api/v1/auth/login"))
        .map(|r| body_of(r).to_string())
        .collect();
    if login_bodies.len() != 2 {
        let all: Vec<String> = log
            .iter()
            .map(|r| r.lines().next().unwrap_or_default().to_string())
            .collect();
        panic!(
            "应有两次登录请求，实际 {} 次。全部请求：{all:#?}",
            login_bodies.len()
        );
    }
    assert!(login_bodies[0].contains("\"email\""), "{}", login_bodies[0]);
    assert!(
        !login_bodies[0].contains("\"username\""),
        "不得用 username 字段: {}",
        login_bodies[0]
    );
    assert!(login_bodies[1].contains("totp_code"), "{}", login_bodies[1]);
}

#[tokio::test]
async fn wrong_password_is_reported_as_auth_failure() {
    let site = spawn_fake_sub2api();
    let dir = tempfile::tempdir().expect("临时目录");
    std::fs::create_dir_all(dir.path().join("home")).unwrap();
    let service = build_service(dir.path(), &site.base_url);

    let summary = service.add_site(&site.base_url).await.expect("识别");
    let err = service
        .login(summary.id, Credentials::new("me@example.com", "wrong"))
        .await
        .expect_err("密码错必须失败");
    assert!(
        matches!(err, tianshu_relay_core::Error::AuthFailed(_)),
        "{err:?}"
    );
    assert!(
        !err.to_string().contains("wrong"),
        "错误串不得回显密码: {err}"
    );
}

#[tokio::test]
async fn unauthenticated_key_list_is_rejected() {
    // 站点在没有 Bearer 时回 401 → 适配器必须映射成 AuthFailed（而不是把空列表当成功）
    let site = spawn_fake_sub2api();
    let dir = tempfile::tempdir().expect("临时目录");
    std::fs::create_dir_all(dir.path().join("home")).unwrap();
    let service = build_service(dir.path(), &site.base_url);

    let summary = service.add_site(&site.base_url).await.expect("识别");
    let err = service
        .list_keys(summary.id)
        .await
        .expect_err("未登录必须失败");
    // 服务层在会话缺失时先报「尚未登录」，这也是可接受的明确失败
    assert!(
        matches!(err, tianshu_relay_core::Error::AuthFailed(_)),
        "{err:?}"
    );
}
