//! OpenID Connect login (authorization code flow with PKCE).
//! Users are matched by `sub`, or by `preferred_username`/`email` for pre-provisioned accounts.
use crate::auth::new_token;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    response::Redirect,
    routing::get,
    Router,
};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::time::Instant;
use uuid::Uuid;

async fn client(state: &AppState) -> ApiResult<CoreClient> {
    let cfg = state.cfg.oidc.as_ref().ok_or_else(|| ApiError::bad("OIDC is not configured"))?;
    let issuer = IssuerUrl::new(cfg.issuer.clone()).map_err(|e| ApiError::Internal(e.to_string()))?;
    let meta = CoreProviderMetadata::discover_async(issuer, async_http_client).await.map_err(|e| ApiError::Internal(format!("oidc discovery: {e}")))?;
    let redirect = format!("{}/api/v1/auth/oidc/callback", state.cfg.public_url.trim_end_matches('/'));
    Ok(CoreClient::from_provider_metadata(meta, ClientId::new(cfg.client_id.clone()), Some(ClientSecret::new(cfg.client_secret.clone())))
        .set_redirect_uri(RedirectUrl::new(redirect).map_err(|e| ApiError::Internal(e.to_string()))?))
}

async fn login(State(state): State<AppState>) -> ApiResult<Redirect> {
    let client = client(&state).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, csrf, nonce) = client
        .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("email".into()))
        .set_pkce_challenge(challenge)
        .url();
    let mut pending = state.oidc_pending.lock().unwrap();
    pending.retain(|_, (_, _, at)| at.elapsed().as_secs() < 600);
    pending.insert(csrf.secret().clone(), (nonce.secret().clone(), verifier.secret().clone(), Instant::now()));
    Ok(Redirect::to(url.as_str()))
}

#[derive(Deserialize)]
struct Callback {
    code: String,
    state: String,
}

async fn callback(State(state): State<AppState>, Query(q): Query<Callback>) -> ApiResult<Redirect> {
    let (nonce, verifier, at) = state.oidc_pending.lock().unwrap().remove(&q.state).ok_or_else(|| ApiError::bad("unknown or expired login"))?;
    if at.elapsed().as_secs() > 600 {
        return Err(ApiError::bad("login expired"));
    }
    let client = client(&state).await?;
    let tokens = client
        .exchange_code(AuthorizationCode::new(q.code))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(async_http_client)
        .await
        .map_err(|e| ApiError::Unauthorized(format!("code exchange failed: {e}")))?;
    let id_token = tokens.id_token().ok_or_else(|| ApiError::Unauthorized("no id_token".into()))?;
    let claims = id_token.claims(&client.id_token_verifier(), &Nonce::new(nonce)).map_err(|e| ApiError::Unauthorized(format!("invalid id_token: {e}")))?;
    let sub = claims.subject().as_str().to_string();
    let name = claims
        .preferred_username()
        .map(|u| u.as_str().to_string())
        .or_else(|| claims.email().map(|e| e.as_str().to_string()))
        .map(|n| n.to_lowercase());

    let cfg = state.cfg.oidc.as_ref().unwrap();
    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(4242)").execute(&mut *tx).await?;
    let mut user: Option<(Uuid, bool)> = sqlx::query("SELECT id, disabled FROM users WHERE oidc_sub = $1").bind(&sub).fetch_optional(&mut *tx).await?.map(|r| (r.get("id"), r.get("disabled")));
    if user.is_none() {
        if let Some(n) = &name {
            user = sqlx::query("UPDATE users SET oidc_sub = $1 WHERE username = $2 AND auth_provider = 'oidc' AND oidc_sub IS NULL RETURNING id, disabled")
                .bind(&sub)
                .bind(n)
                .fetch_optional(&mut *tx)
                .await?
                .map(|r| (r.get("id"), r.get("disabled")));
        }
    }
    if user.is_none() && cfg.auto_provision {
        let n = name.clone().unwrap_or_else(|| format!("user-{}", &sub[..sub.len().min(8)]));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(&mut *tx).await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, username, role, auth_provider, oidc_sub) VALUES ($1, $2, $3, 'oidc', $4)")
            .bind(id)
            .bind(&n)
            .bind(if count == 0 { "admin" } else { "user" })
            .bind(&sub)
            .execute(&mut *tx)
            .await?;
        user = Some((id, false));
    }
    tx.commit().await?;
    let (id, disabled) = user.ok_or_else(|| ApiError::Forbidden("no account for this identity; ask an admin to create one".into()))?;
    if disabled {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    let token = new_token();
    sqlx::query("INSERT INTO tokens (id, user_id, kind, token_hash, name) VALUES ($1, $2, 'device', $3, 'web (oidc)')")
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(Sha256::digest(token.as_bytes()).to_vec())
        .execute(&state.db)
        .await?;
    Ok(Redirect::to(&format!("{}/#oidc-token={}", state.cfg.public_url.trim_end_matches('/'), token)))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/auth/oidc/login", get(login)).route("/auth/oidc/callback", get(callback))
}
