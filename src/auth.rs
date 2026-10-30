//! Accounts, sessions, mandatory second factor (TOTP / recovery codes / WebAuthn security keys).
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use argon2::password_hash::{rand_core::OsRng as PwOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::{
    async_trait,
    extract::{FromRequestParts, Path, Query, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    routing::{delete, get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use syncloom_core::api::*;
use syncloom_core::vault::{KdfParams, VaultBundle};
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;
use webauthn_rs::prelude::*;

const MFA_TOKEN_TTL_MIN: i64 = 5;
const ENROLL_TOKEN_TTL_MIN: i64 = 30;

// ---------- tokens & extractors ----------

pub fn hash_token(t: &str) -> Vec<u8> {
    Sha256::digest(t.as_bytes()).to_vec()
}

pub fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

async fn issue_token(state: &AppState, user: Uuid, kind: &str, name: &str, ttl_min: Option<i64>) -> ApiResult<String> {
    let token = new_token();
    sqlx::query(
        "INSERT INTO tokens (id, user_id, kind, token_hash, name, expires_at)
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $6::bigint IS NULL THEN NULL ELSE now() + make_interval(mins => $6::int) END)",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .bind(kind)
    .bind(hash_token(&token))
    .bind(name)
    .bind(ttl_min)
    .execute(&state.db)
    .await?;
    Ok(token)
}

#[derive(Debug, Clone)]
pub struct AuthedUser {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub token_id: Uuid,
    pub kind: String,
}

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

pub async fn authenticate(state: &AppState, headers: &HeaderMap, allowed: &[&str]) -> ApiResult<AuthedUser> {
    let token = bearer(headers).ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;
    let row = sqlx::query(
        "SELECT t.id AS token_id, t.kind, t.expires_at < now() AS expired, u.id, u.username, u.role, u.disabled
         FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = $1",
    )
    .bind(hash_token(token))
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("invalid token".into()))?;
    let expired: Option<bool> = row.try_get("expired")?;
    let disabled: bool = row.try_get("disabled")?;
    let kind: String = row.try_get("kind")?;
    if expired == Some(true) || disabled || !allowed.contains(&kind.as_str()) {
        return Err(ApiError::Unauthorized("invalid token".into()));
    }
    let token_id: Uuid = row.try_get("token_id")?;
    // best-effort, throttled to once per minute
    let _ = sqlx::query("UPDATE tokens SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval '1 minute'")
        .bind(token_id)
        .execute(&state.db)
        .await;
    Ok(AuthedUser { id: row.try_get("id")?, username: row.try_get("username")?, role: row.try_get("role")?, token_id, kind })
}

macro_rules! extractor {
    ($name:ident, $kinds:expr) => {
        pub struct $name(pub AuthedUser);
        #[async_trait]
        impl FromRequestParts<AppState> for $name {
            type Rejection = ApiError;
            async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
                Ok($name(authenticate(state, &parts.headers, $kinds).await?))
            }
        }
    };
}
extractor!(Auth, &["device"]);
extractor!(AnyAuth, &["device", "enroll"]);
extractor!(MfaAuth, &["mfa"]);

pub struct Admin(pub AuthedUser);
#[async_trait]
impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let u = authenticate(state, &parts.headers, &["device"]).await?;
        if u.role != "admin" {
            return Err(ApiError::Forbidden("admin only".into()));
        }
        Ok(Admin(u))
    }
}

// ---------- password / secrets ----------

pub async fn hash_secret(secret: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut PwOsRng);
        Argon2::default().hash_password(secret.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
}

pub async fn verify_secret(secret: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash).map(|h| Argon2::default().verify_password(secret.as_bytes(), &h).is_ok()).unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        let salt = SaltString::generate(&mut PwOsRng);
        Argon2::default().hash_password(b"dummy", &salt).unwrap().to_string()
    })
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn make_totp(secret: Vec<u8>, username: &str) -> ApiResult<TOTP> {
    TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, Some("Syncloom".into()), username.to_string())
        .map_err(|e| ApiError::Internal(format!("totp: {e}")))
}

/// Returns the matched time step if `code` is valid within ±1 step.
fn check_totp(totp: &TOTP, code: &str) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    let now = now_secs();
    for off in [-1i64, 0, 1] {
        let step = (now / 30) as i64 + off;
        if step < 0 {
            continue;
        }
        let expected = totp.generate((step as u64) * 30);
        if expected.as_bytes().ct_eq(code.as_bytes()).into() {
            return Some(step);
        }
    }
    None
}

fn recovery_hash(code: &str) -> Vec<u8> {
    let norm: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
    Sha256::digest(norm.as_bytes()).to_vec()
}

async fn make_recovery_codes(state: &AppState, user: Uuid) -> ApiResult<Vec<String>> {
    let mut codes = Vec::new();
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1").bind(user).execute(&mut *tx).await?;
    for _ in 0..10 {
        let mut b = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let h = hex::encode(b);
        let code = format!("{}-{}-{}", &h[0..4], &h[4..8], &h[8..12]);
        sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user)
            .bind(recovery_hash(&code))
            .execute(&mut *tx)
            .await?;
        codes.push(code);
    }
    tx.commit().await?;
    Ok(codes)
}

async fn mfa_methods(state: &AppState, user: Uuid) -> ApiResult<Vec<String>> {
    let mut m = Vec::new();
    let totp: i64 = sqlx::query_scalar("SELECT count(*) FROM totp_authenticators WHERE user_id = $1 AND confirmed").bind(user).fetch_one(&state.db).await?;
    if totp > 0 {
        m.push("totp".to_string());
    }
    let wa: i64 = sqlx::query_scalar("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1").bind(user).fetch_one(&state.db).await?;
    if wa > 0 {
        m.push("webauthn".to_string());
    }
    if !m.is_empty() {
        m.push("recovery".to_string());
    }
    Ok(m)
}

async fn user_info(state: &AppState, id: Uuid) -> ApiResult<UserInfo> {
    let r = sqlx::query("SELECT username, role, quota_bytes, auth_provider FROM users WHERE id = $1").bind(id).fetch_one(&state.db).await?;
    let quota: Option<i64> = r.try_get("quota_bytes")?;
    Ok(UserInfo {
        id: id.to_string(),
        username: r.try_get("username")?,
        role: r.try_get("role")?,
        quota_bytes: db::effective_quota(&state.db, quota).await?,
        used_bytes: db::used_bytes(&state.db, id).await?,
        mfa_methods: mfa_methods(state, id).await?,
        auth_provider: r.try_get("auth_provider")?,
    })
}

fn valid_username(u: &str) -> bool {
    (3..=64).contains(&u.len()) && u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn require_local(state: &AppState) -> ApiResult<()> {
    if state.cfg.local_auth {
        Ok(())
    } else {
        Err(ApiError::Forbidden("built-in accounts are disabled; use OIDC".into()))
    }
}

// ---------- handlers ----------

#[derive(Deserialize)]
struct PreloginQuery {
    username: String,
}

#[derive(serde::Serialize)]
struct AuthConfig {
    local_auth: bool,
    oidc: bool,
    /// No account exists yet: the first registration creates the admin.
    setup_required: bool,
    webauthn: bool,
}

/// Public: lets the sign-in page decide what to offer.
async fn auth_config(State(state): State<AppState>) -> ApiResult<Json<AuthConfig>> {
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(&state.db).await?;
    Ok(Json(AuthConfig { local_auth: state.cfg.local_auth, oidc: state.cfg.oidc.is_some(), setup_required: users == 0, webauthn: state.webauthn.is_some() }))
}

async fn prelogin(State(state): State<AppState>, Query(q): Query<PreloginQuery>) -> ApiResult<Json<PreloginResp>> {
    let username = q.username.trim().to_lowercase();
    let vault: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT vault FROM users WHERE username = $1 AND auth_provider = 'local'").bind(&username).fetch_optional(&state.db).await?.flatten();
    let kdf = vault
        .and_then(|v| serde_json::from_value::<VaultBundle>(v).ok())
        .map(|b| b.kdf)
        .unwrap_or_else(|| KdfParams::fake_for(&username, &state.server_secret));
    Ok(Json(PreloginResp { kdf }))
}

async fn register(State(state): State<AppState>, Json(req): Json<RegisterReq>) -> ApiResult<Json<LoginResp>> {
    require_local(&state)?;
    let username = req.username.trim().to_lowercase();
    if !valid_username(&username) {
        return Err(ApiError::bad("username must be 3-64 characters of a-z 0-9 . _ -"));
    }
    if req.vault.public_key.len() != 32 {
        return Err(ApiError::bad("invalid vault"));
    }
    let hash = hash_secret(req.auth_secret).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(4242)").execute(&mut *tx).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(&mut *tx).await?;
    let role = if count == 0 {
        "admin"
    } else {
        let code = req.invite.as_deref().ok_or_else(|| ApiError::Forbidden("an invite is required".into()))?;
        let valid = sqlx::query("SELECT 1 FROM invites WHERE code_hash = $1 AND used_by IS NULL AND expires_at > now() FOR UPDATE")
            .bind(hash_token(code))
            .fetch_optional(&mut *tx)
            .await?;
        if valid.is_none() {
            return Err(ApiError::Forbidden("invalid or expired invite".into()));
        }
        "user"
    };
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, username, role, auth_hash, vault, public_key) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(id)
        .bind(&username)
        .bind(role)
        .bind(hash)
        .bind(serde_json::to_value(&req.vault).map_err(|e| ApiError::Internal(e.to_string()))?)
        .bind(&req.vault.public_key)
        .execute(&mut *tx)
        .await
        .map_err(|e| match ApiError::from(e) {
            ApiError::Conflict(_) => ApiError::conflict("username already taken"),
            o => o,
        })?;
    if count > 0 {
        // consume the invite (re-hash from request so we mark exactly this one)
        sqlx::query("UPDATE invites SET used_by = $2 WHERE code_hash = $1")
            .bind(hash_token(req.invite.as_deref().unwrap_or("")))
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let token = issue_token(&state, id, "enroll", &req.device_name, Some(ENROLL_TOKEN_TTL_MIN)).await?;
    Ok(Json(LoginResp { status: "enroll_required".into(), token, methods: vec![] }))
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> ApiResult<Json<LoginResp>> {
    require_local(&state)?;
    let username = req.username.trim().to_lowercase();
    if !state.check_login_allowed(&username) {
        return Err(ApiError::TooManyRequests("too many failed attempts, try again later".into()));
    }
    let row = sqlx::query("SELECT id, auth_hash, disabled FROM users WHERE username = $1 AND auth_provider = 'local'")
        .bind(&username)
        .fetch_optional(&state.db)
        .await?;
    let (hash, id, disabled) = match &row {
        Some(r) => (r.try_get::<Option<String>, _>("auth_hash")?.unwrap_or_default(), Some(r.try_get::<Uuid, _>("id")?), r.try_get::<bool, _>("disabled")?),
        None => (dummy_hash().to_string(), None, false),
    };
    let ok = verify_secret(req.auth_secret, hash).await;
    let id = match (ok, id, disabled) {
        (true, Some(id), false) => id,
        _ => {
            state.record_login_failure(&username);
            return Err(ApiError::Unauthorized("invalid username or password".into()));
        }
    };
    state.clear_login_failures(&username);
    let methods = mfa_methods(&state, id).await?;
    if methods.is_empty() {
        let token = issue_token(&state, id, "enroll", &req.device_name, Some(ENROLL_TOKEN_TTL_MIN)).await?;
        return Ok(Json(LoginResp { status: "enroll_required".into(), token, methods }));
    }
    let token = issue_token(&state, id, "mfa", &req.device_name, Some(MFA_TOKEN_TTL_MIN)).await?;
    Ok(Json(LoginResp { status: "mfa_required".into(), token, methods }))
}

async fn finish_mfa(state: &AppState, user: &AuthedUser, device_name: &str) -> ApiResult<LoginResp> {
    sqlx::query("DELETE FROM tokens WHERE id = $1").bind(user.token_id).execute(&state.db).await?;
    let token = issue_token(state, user.id, "device", device_name, None).await?;
    Ok(LoginResp { status: "ok".into(), token, methods: vec![] })
}

async fn mfa_verify(State(state): State<AppState>, MfaAuth(user): MfaAuth, Json(req): Json<MfaVerifyReq>) -> ApiResult<Json<LoginResp>> {
    let key = format!("mfa:{}", user.id);
    if !state.check_login_allowed(&key) {
        return Err(ApiError::TooManyRequests("too many failed attempts".into()));
    }
    let valid = match req.method.as_str() {
        "totp" => {
            let rows = sqlx::query("SELECT id, secret FROM totp_authenticators WHERE user_id = $1 AND confirmed").bind(user.id).fetch_all(&state.db).await?;
            let mut ok = false;
            for r in rows {
                let secret: String = r.try_get("secret")?;
                let totp = make_totp(hex::decode(secret).map_err(|e| ApiError::Internal(e.to_string()))?, &user.username)?;
                if let Some(step) = check_totp(&totp, &req.code) {
                    // reject replays of an already used time step for this authenticator
                    ok = sqlx::query("UPDATE totp_authenticators SET last_step = $2 WHERE id = $1 AND last_step < $2")
                        .bind(r.try_get::<Uuid, _>("id")?)
                        .bind(step)
                        .execute(&state.db)
                        .await?
                        .rows_affected()
                        == 1;
                    break;
                }
            }
            ok
        }
        "recovery" => {
            sqlx::query("UPDATE recovery_codes SET used = true WHERE user_id = $1 AND code_hash = $2 AND used = false")
                .bind(user.id)
                .bind(recovery_hash(&req.code))
                .execute(&state.db)
                .await?
                .rows_affected()
                == 1
        }
        _ => return Err(ApiError::bad("unknown method")),
    };
    if !valid {
        state.record_login_failure(&key);
        return Err(ApiError::Unauthorized("invalid code".into()));
    }
    state.clear_login_failures(&key);
    Ok(Json(finish_mfa(&state, &user, &req.device_name).await?))
}

async fn totp_setup(State(state): State<AppState>, AnyAuth(user): AnyAuth, body: Option<Json<TotpSetupReq>>) -> ApiResult<Json<TotpSetupResp>> {
    let name = body.map(|b| b.0.name).filter(|n| !n.trim().is_empty()).unwrap_or_else(|| "Authenticator app".into());
    let mut secret = vec![0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let id = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM totp_authenticators WHERE user_id = $1 AND NOT confirmed").bind(user.id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO totp_authenticators (id, user_id, name, secret) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(user.id)
        .bind(name.trim())
        .bind(hex::encode(&secret))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let totp = make_totp(secret, &user.username)?;
    Ok(Json(TotpSetupResp { id: id.to_string(), secret: totp.get_secret_base32(), otpauth_url: totp.get_url() }))
}

async fn has_recovery_codes(state: &AppState, user: Uuid) -> ApiResult<bool> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery_codes WHERE user_id = $1").bind(user).fetch_one(&state.db).await?;
    Ok(n > 0)
}

async fn totp_confirm(State(state): State<AppState>, AnyAuth(user): AnyAuth, Json(req): Json<TotpConfirmReq>) -> ApiResult<Json<TotpConfirmResp>> {
    let id = crate::db::parse_uuid(&req.id)?;
    let r = sqlx::query("SELECT secret FROM totp_authenticators WHERE id = $1 AND user_id = $2 AND NOT confirmed")
        .bind(id)
        .bind(user.id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::conflict("no pending TOTP setup"))?;
    let secret: String = r.try_get("secret")?;
    let totp = make_totp(hex::decode(secret).map_err(|e| ApiError::Internal(e.to_string()))?, &user.username)?;
    let step = check_totp(&totp, &req.code).ok_or_else(|| ApiError::Unauthorized("invalid code".into()))?;
    sqlx::query("UPDATE totp_authenticators SET confirmed = true, last_step = $2 WHERE id = $1").bind(id).bind(step).execute(&state.db).await?;
    let codes = if has_recovery_codes(&state, user.id).await? { vec![] } else { make_recovery_codes(&state, user.id).await? };
    let token = if user.kind == "enroll" { finish_mfa(&state, &user, &req.device_name).await?.token } else { String::new() };
    Ok(Json(TotpConfirmResp { recovery_codes: codes, token }))
}

/// All enrolled second factors (authenticator apps and security keys).
async fn list_mfa(State(state): State<AppState>, Auth(user): Auth) -> ApiResult<Json<Vec<MfaMethodDto>>> {
    let rows = sqlx::query(
        "SELECT id, 'totp' AS kind, name, created_at FROM totp_authenticators WHERE user_id = $1 AND confirmed
         UNION ALL SELECT id, 'webauthn', name, created_at FROM webauthn_credentials WHERE user_id = $1
         ORDER BY created_at",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    rows.iter()
        .map(|r| {
            let c: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
            Ok(MfaMethodDto { id: r.try_get::<Uuid, _>("id")?.to_string(), kind: r.try_get("kind")?, name: r.try_get("name")?, created_at: c.timestamp_millis() })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

async fn rename_mfa(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>, Json(req): Json<RenameMfaReq>) -> ApiResult<StatusCode> {
    let name = req.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::bad("name must be 1-64 characters"));
    }
    let a = sqlx::query("UPDATE totp_authenticators SET name = $3 WHERE id = $1 AND user_id = $2").bind(id).bind(user.id).bind(name).execute(&state.db).await?.rows_affected();
    let b = sqlx::query("UPDATE webauthn_credentials SET name = $3 WHERE id = $1 AND user_id = $2").bind(id).bind(user.id).bind(name).execute(&state.db).await?.rows_affected();
    if a + b == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Remove one factor. The last remaining factor cannot be removed (the account must always have one).
async fn delete_mfa(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    let total: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM totp_authenticators WHERE user_id = $1 AND confirmed)
              + (SELECT count(*) FROM webauthn_credentials WHERE user_id = $1)",
    )
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;
    if total <= 1 {
        return Err(ApiError::conflict("cannot remove your only second factor; add another one first"));
    }
    let a = sqlx::query("DELETE FROM totp_authenticators WHERE id = $1 AND user_id = $2 AND confirmed").bind(id).bind(user.id).execute(&mut *tx).await?.rows_affected();
    let b = sqlx::query("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2").bind(id).bind(user.id).execute(&mut *tx).await?.rows_affected();
    if a + b == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn new_recovery_codes(State(state): State<AppState>, Auth(user): Auth) -> ApiResult<Json<RecoveryCodesResp>> {
    Ok(Json(RecoveryCodesResp { recovery_codes: make_recovery_codes(&state, user.id).await? }))
}

// ----- WebAuthn (hardware security keys) -----

fn webauthn(state: &AppState) -> ApiResult<&Webauthn> {
    state.webauthn.as_ref().ok_or_else(|| ApiError::Internal("webauthn not configured".into()))
}

async fn load_keys(state: &AppState, user: Uuid) -> ApiResult<Vec<(Uuid, SecurityKey)>> {
    let rows = sqlx::query("SELECT id, passkey FROM webauthn_credentials WHERE user_id = $1").bind(user).fetch_all(&state.db).await?;
    rows.iter()
        .map(|r| {
            let v: serde_json::Value = r.try_get("passkey")?;
            let k: SecurityKey = serde_json::from_value(v).map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok((r.try_get("id")?, k))
        })
        .collect()
}

async fn webauthn_register_start(State(state): State<AppState>, AnyAuth(user): AnyAuth) -> ApiResult<Json<CreationChallengeResponse>> {
    let wa = webauthn(&state)?;
    let existing: Vec<CredentialID> = load_keys(&state, user.id).await?.iter().map(|(_, k)| k.cred_id().clone()).collect();
    let (challenge, reg) = wa
        .start_securitykey_registration(user.id, &user.username, &user.username, Some(existing), None, None)
        .map_err(|e| ApiError::bad(format!("webauthn: {e}")))?;
    state.wa_reg.lock().unwrap().insert(user.id, (reg, Instant::now()));
    Ok(Json(challenge))
}

#[derive(Deserialize)]
struct WaFinishQuery {
    #[serde(default)]
    name: String,
    #[serde(default)]
    device_name: String,
}

async fn webauthn_register_finish(
    State(state): State<AppState>,
    AnyAuth(user): AnyAuth,
    Query(q): Query<WaFinishQuery>,
    Json(cred): Json<RegisterPublicKeyCredential>,
) -> ApiResult<Json<TotpConfirmResp>> {
    let wa = webauthn(&state)?;
    let (reg, at) = state.wa_reg.lock().unwrap().remove(&user.id).ok_or_else(|| ApiError::bad("no registration in progress"))?;
    if at.elapsed().as_secs() > 300 {
        return Err(ApiError::bad("registration expired"));
    }
    let key = wa.finish_securitykey_registration(&cred, &reg).map_err(|e| ApiError::bad(format!("webauthn: {e}")))?;
    if load_keys(&state, user.id).await?.iter().any(|(_, k)| k.cred_id() == key.cred_id()) {
        return Err(ApiError::conflict("this security key is already enrolled"));
    }
    sqlx::query("INSERT INTO webauthn_credentials (id, user_id, name, passkey) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4())
        .bind(user.id)
        .bind(if q.name.is_empty() { "security key" } else { &q.name })
        .bind(serde_json::to_value(&key).map_err(|e| ApiError::Internal(e.to_string()))?)
        .execute(&state.db)
        .await?;
    let codes = if has_recovery_codes(&state, user.id).await? { vec![] } else { make_recovery_codes(&state, user.id).await? };
    let token = if user.kind == "enroll" { finish_mfa(&state, &user, &q.device_name).await?.token } else { String::new() };
    Ok(Json(TotpConfirmResp { recovery_codes: codes, token }))
}

async fn webauthn_login_start(State(state): State<AppState>, MfaAuth(user): MfaAuth) -> ApiResult<Json<RequestChallengeResponse>> {
    let wa = webauthn(&state)?;
    let keys: Vec<SecurityKey> = load_keys(&state, user.id).await?.into_iter().map(|(_, k)| k).collect();
    if keys.is_empty() {
        return Err(ApiError::bad("no security key enrolled"));
    }
    let (challenge, st) = wa.start_securitykey_authentication(&keys).map_err(|e| ApiError::bad(format!("webauthn: {e}")))?;
    state.wa_auth.lock().unwrap().insert(user.id, (st, Instant::now()));
    Ok(Json(challenge))
}

async fn webauthn_login_finish(
    State(state): State<AppState>,
    MfaAuth(user): MfaAuth,
    Query(q): Query<WaFinishQuery>,
    Json(cred): Json<PublicKeyCredential>,
) -> ApiResult<Json<LoginResp>> {
    let wa = webauthn(&state)?;
    let (st, at) = state.wa_auth.lock().unwrap().remove(&user.id).ok_or_else(|| ApiError::bad("no authentication in progress"))?;
    if at.elapsed().as_secs() > 300 {
        return Err(ApiError::bad("authentication expired"));
    }
    let result = wa.finish_securitykey_authentication(&cred, &st).map_err(|_| ApiError::Unauthorized("security key rejected".into()))?;
    for (id, mut key) in load_keys(&state, user.id).await? {
        if key.update_credential(&result) == Some(true) {
            sqlx::query("UPDATE webauthn_credentials SET passkey = $2 WHERE id = $1")
                .bind(id)
                .bind(serde_json::to_value(&key).map_err(|e| ApiError::Internal(e.to_string()))?)
                .execute(&state.db)
                .await?;
        }
    }
    Ok(Json(finish_mfa(&state, &user, &q.device_name).await?))
}

// ----- session / account -----

async fn logout(State(state): State<AppState>, Auth(user): Auth) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM tokens WHERE id = $1").bind(user.token_id).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(State(state): State<AppState>, Auth(user): Auth) -> ApiResult<Json<MeResp>> {
    let vault: Option<serde_json::Value> = sqlx::query_scalar("SELECT vault FROM users WHERE id = $1").bind(user.id).fetch_one(&state.db).await?;
    Ok(Json(MeResp {
        user: user_info(&state, user.id).await?,
        vault: vault.and_then(|v| serde_json::from_value(v).ok()),
    }))
}

/// OIDC users have no password, so they create their vault passphrase after the first login.
async fn put_vault(State(state): State<AppState>, Auth(user): Auth, Json(vault): Json<VaultBundle>) -> ApiResult<StatusCode> {
    if vault.public_key.len() != 32 {
        return Err(ApiError::bad("invalid vault"));
    }
    let r = sqlx::query("UPDATE users SET vault = $2, public_key = $3 WHERE id = $1 AND vault IS NULL")
        .bind(user.id)
        .bind(serde_json::to_value(&vault).map_err(|e| ApiError::Internal(e.to_string()))?)
        .bind(&vault.public_key)
        .execute(&state.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::conflict("vault already exists"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn change_password(State(state): State<AppState>, Auth(user): Auth, Json(req): Json<ChangePasswordReq>) -> ApiResult<StatusCode> {
    let r = sqlx::query("SELECT auth_hash, auth_provider, vault FROM users WHERE id = $1").bind(user.id).fetch_one(&state.db).await?;
    let provider: String = r.try_get("auth_provider")?;
    if provider != "local" {
        return Err(ApiError::bad("password is managed by the identity provider"));
    }
    let hash: String = r.try_get::<Option<String>, _>("auth_hash")?.unwrap_or_default();
    if !verify_secret(req.old_auth_secret, hash).await {
        return Err(ApiError::Unauthorized("wrong password".into()));
    }
    // the public key and wrapped private key must not change: this only re-wraps the master key
    let old: VaultBundle = serde_json::from_value(r.try_get("vault")?).map_err(|e| ApiError::Internal(e.to_string()))?;
    if old.public_key != req.vault.public_key || old.wrapped_private_key != req.vault.wrapped_private_key || old.wrapped_master_recovery != req.vault.wrapped_master_recovery {
        return Err(ApiError::bad("vault keys must not change"));
    }
    let new_hash = hash_secret(req.new_auth_secret).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET auth_hash = $2, vault = $3 WHERE id = $1")
        .bind(user.id)
        .bind(new_hash)
        .bind(serde_json::to_value(&req.vault).map_err(|e| ApiError::Internal(e.to_string()))?)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM tokens WHERE user_id = $1 AND id <> $2").bind(user.id).bind(user.token_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn devices(State(state): State<AppState>, Auth(user): Auth) -> ApiResult<Json<Vec<DeviceInfo>>> {
    let rows = sqlx::query("SELECT id, name, created_at, last_seen_at FROM tokens WHERE user_id = $1 AND kind = 'device' ORDER BY created_at")
        .bind(user.id)
        .fetch_all(&state.db)
        .await?;
    rows.iter()
        .map(|r| {
            let id: Uuid = r.try_get("id")?;
            let c: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
            let l: chrono::DateTime<chrono::Utc> = r.try_get("last_seen_at")?;
            Ok(DeviceInfo { id: id.to_string(), name: r.try_get("name")?, created_at: c.timestamp_millis(), last_seen_at: l.timestamp_millis(), current: id == user.token_id })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

async fn revoke_device(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    let r = sqlx::query("DELETE FROM tokens WHERE id = $1 AND user_id = $2 AND kind = 'device'").bind(id).bind(user.id).execute(&state.db).await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn user_pubkey(State(state): State<AppState>, Auth(_): Auth, Path(username): Path<String>) -> ApiResult<Json<PublicKeyResp>> {
    let pk: Option<Vec<u8>> = sqlx::query_scalar("SELECT public_key FROM users WHERE username = $1 AND disabled = false")
        .bind(username.to_lowercase())
        .fetch_optional(&state.db)
        .await?
        .flatten();
    Ok(Json(PublicKeyResp { public_key: pk.ok_or(ApiError::NotFound)? }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/config", get(auth_config))
        .route("/auth/prelogin", get(prelogin))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/mfa/verify", post(mfa_verify))
        .route("/auth/totp/setup", post(totp_setup))
        .route("/auth/totp/confirm", post(totp_confirm))
        .route("/auth/webauthn/register/start", post(webauthn_register_start))
        .route("/auth/webauthn/register/finish", post(webauthn_register_finish))
        .route("/auth/webauthn/login/start", post(webauthn_login_start))
        .route("/auth/webauthn/login/finish", post(webauthn_login_finish))
        .route("/auth/logout", post(logout))
        .route("/me", get(me))
        .route("/me/vault", put(put_vault))
        .route("/me/password", post(change_password))
        .route("/me/mfa", get(list_mfa))
        .route("/me/mfa/:id", axum::routing::patch(rename_mfa).delete(delete_mfa))
        .route("/me/recovery-codes", post(new_recovery_codes))
        .route("/me/devices", get(devices))
        .route("/me/devices/:id", delete(revoke_device))
        .route("/users/:username/pubkey", get(user_pubkey))
}
