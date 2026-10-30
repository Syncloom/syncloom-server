#![allow(dead_code)]
use std::time::{SystemTime, UNIX_EPOCH};
use syncloom_core::client::{Auth, Client, LoginOutcome};
use syncloom_core::vault::KdfParams;
use syncloom_server::{app, build_state, config::*, state::AppState};
use totp_rs::TOTP;

pub const ADMIN_DB: &str = "postgres://postgres:syncloom@localhost:55432/postgres";

pub struct TestServer {
    pub base: String,
    pub state: AppState,
    pub blob_dir: tempfile::TempDir,
    pub db_name: String,
}

pub async fn start() -> TestServer {
    start_with(|_| {}).await
}

pub async fn start_with(tweak: impl FnOnce(&mut Config)) -> TestServer {
    let admin = sqlx::PgPool::connect(ADMIN_DB).await.expect("postgres must be running on :55432 (see DEPLOY.md)");
    let db_name = format!("t_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\"")).execute(&admin).await.unwrap();
    let blob_dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = Config {
        database_url: format!("postgres://postgres:syncloom@localhost:55432/{db_name}"),
        listen_addr: format!("127.0.0.1:{port}"),
        public_url: format!("http://localhost:{port}"),
        blobs: BlobBackend::Fs(blob_dir.path().to_path_buf()),
        oidc: None,
        local_auth: true,
        cors_origins: vec![],
        maintenance_interval_secs: 3600,
    };
    tweak(&mut cfg);
    let state = build_state(cfg).await.unwrap();
    let router = app(state.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    TestServer { base: format!("http://127.0.0.1:{port}"), state, blob_dir, db_name }
}

pub fn totp_code(url: &str, offset_steps: i64) -> String {
    let t = TOTP::from_url_unchecked(url).unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    t.generate((now + offset_steps * 30) as u64)
}

pub struct User {
    pub name: String,
    pub password: String,
    pub token: String,
    pub client: Client,
    pub totp_url: String,
    pub recovery_codes: Vec<String>,
    pub recovery_key: String,
}

/// Register (first user = admin, later users need `invite`), enroll TOTP, and connect.
pub async fn new_user(srv: &TestServer, name: &str, invite: Option<&str>) -> User {
    let auth = Auth::new(&srv.base);
    let password = format!("pw-{name}-correct horse");
    let reg = auth.register_with(name, &password, invite, "test", KdfParams::fast_for_tests()).await.unwrap();
    let LoginOutcome::EnrollRequired { token: enroll } = reg.outcome else { panic!("expected enrollment") };
    let setup = auth.totp_setup(&enroll, "test app").await.unwrap();
    let code = totp_code(&setup.otpauth_url, 0);
    let confirm = auth.totp_confirm(&enroll, &setup.id, &code, "test-device").await.unwrap();
    assert_eq!(confirm.recovery_codes.len(), 10);
    let client = Client::connect(&srv.base, &confirm.token, &password).await.unwrap();
    User { name: name.into(), password, token: confirm.token, client, totp_url: setup.otpauth_url, recovery_codes: confirm.recovery_codes, recovery_key: reg.recovery_key }
}

pub async fn invite(admin: &User, srv: &TestServer) -> String {
    let r = reqwest::Client::new()
        .post(format!("{}/api/v1/admin/invites", srv.base))
        .bearer_auth(&admin.token)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    r.json::<serde_json::Value>().await.unwrap()["code"].as_str().unwrap().to_string()
}

pub async fn raw(srv: &TestServer, token: &str, method: reqwest::Method, path: &str, body: Option<serde_json::Value>) -> (u16, serde_json::Value) {
    let mut rb = reqwest::Client::new().request(method, format!("{}/api/v1{}", srv.base, path)).bearer_auth(token);
    if let Some(b) = body {
        rb = rb.json(&b);
    }
    let r = rb.send().await.unwrap();
    let status = r.status().as_u16();
    let text = r.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(serde_json::Value::Null))
}

pub fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}
