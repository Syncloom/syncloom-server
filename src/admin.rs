use crate::auth::{hash_token, new_token, Admin};
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, patch, post},
    Json, Router,
};
use serde::Deserialize;
use sqlx::Row;
use syncloom_core::api::*;
use uuid::Uuid;

async fn list_users(State(state): State<AppState>, Admin(_): Admin) -> ApiResult<Json<Vec<AdminUserDto>>> {
    let rows = sqlx::query(
        "SELECT u.id, u.username, u.role, u.quota_bytes, u.disabled, u.auth_provider,
                (SELECT count(*) FROM totp_authenticators t WHERE t.user_id = u.id AND t.confirmed) AS totp,
                (SELECT count(*) FROM webauthn_credentials w WHERE w.user_id = u.id) AS wa
         FROM users u ORDER BY u.created_at",
    )
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for r in &rows {
        let id: Uuid = r.try_get("id")?;
        let mut methods = vec![];
        if r.try_get::<i64, _>("totp")? > 0 {
            methods.push("totp".to_string());
        }
        if r.try_get::<i64, _>("wa")? > 0 {
            methods.push("webauthn".to_string());
        }
        out.push(AdminUserDto {
            id: id.to_string(),
            username: r.try_get("username")?,
            role: r.try_get("role")?,
            quota_bytes: r.try_get("quota_bytes")?,
            used_bytes: db::used_bytes(&state.db, id).await?,
            disabled: r.try_get("disabled")?,
            mfa_methods: methods,
            auth_provider: r.try_get("auth_provider")?,
        });
    }
    Ok(Json(out))
}

async fn admin_count_after(state: &AppState, changing: Uuid) -> ApiResult<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM users WHERE role = 'admin' AND disabled = false AND id <> $1").bind(changing).fetch_one(&state.db).await?)
}

async fn update_user(State(state): State<AppState>, Admin(me): Admin, Path(id): Path<Uuid>, Json(req): Json<AdminUpdateUserReq>) -> ApiResult<StatusCode> {
    if let Some(role) = &req.role {
        if !["admin", "user"].contains(&role.as_str()) {
            return Err(ApiError::bad("role must be admin or user"));
        }
    }
    let demoting = req.role.as_deref() == Some("user") || req.disabled == Some(true);
    if demoting && admin_count_after(&state, id).await? == 0 {
        return Err(ApiError::conflict("cannot remove the last active admin"));
    }
    let _ = me;
    let r = sqlx::query(
        "UPDATE users SET role = COALESCE($2, role), disabled = COALESCE($3, disabled),
            quota_bytes = CASE WHEN $5 THEN NULL ELSE COALESCE($4, quota_bytes) END WHERE id = $1",
    )
    .bind(id)
    .bind(&req.role)
    .bind(req.disabled)
    .bind(req.quota_bytes)
    .bind(req.clear_quota.unwrap_or(false))
    .execute(&state.db)
    .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    if req.disabled == Some(true) {
        sqlx::query("DELETE FROM tokens WHERE user_id = $1").bind(id).execute(&state.db).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_user(State(state): State<AppState>, Admin(_): Admin, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    if admin_count_after(&state, id).await? == 0 {
        return Err(ApiError::conflict("cannot delete the last active admin"));
    }
    let r = sqlx::query("DELETE FROM users WHERE id = $1").bind(id).execute(&state.db).await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Removes every second factor and signs the user out. Their next login forces re-enrollment.
async fn reset_2fa(State(state): State<AppState>, Admin(_): Admin, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM totp_authenticators WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM webauthn_credentials WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM tokens WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
struct InviteQuery {
    days: Option<i32>,
}

async fn create_invite(State(state): State<AppState>, Admin(me): Admin, Query(q): Query<InviteQuery>) -> ApiResult<Json<CreateInviteResp>> {
    let code = new_token();
    sqlx::query("INSERT INTO invites (code_hash, created_by, expires_at) VALUES ($1, $2, now() + make_interval(days => $3))")
        .bind(hash_token(&code))
        .bind(me.id)
        .bind(q.days.unwrap_or(7).clamp(1, 90))
        .execute(&state.db)
        .await?;
    Ok(Json(CreateInviteResp { code }))
}

#[derive(Deserialize)]
struct CreateOidcUser {
    username: String,
    #[serde(default)]
    role: Option<String>,
}

/// Pre-provision a user who will sign in through OIDC (matched by preferred_username / email).
async fn create_oidc_user(State(state): State<AppState>, Admin(_): Admin, Json(req): Json<CreateOidcUser>) -> ApiResult<StatusCode> {
    if state.cfg.oidc.is_none() {
        return Err(ApiError::bad("OIDC is not configured"));
    }
    let role = req.role.unwrap_or_else(|| "user".into());
    if !["admin", "user"].contains(&role.as_str()) {
        return Err(ApiError::bad("invalid role"));
    }
    sqlx::query("INSERT INTO users (id, username, role, auth_provider) VALUES ($1, $2, $3, 'oidc')")
        .bind(Uuid::new_v4())
        .bind(req.username.trim().to_lowercase())
        .bind(role)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::CREATED)
}

async fn get_settings(State(state): State<AppState>, Admin(_): Admin) -> ApiResult<Json<Settings>> {
    Ok(Json(db::get_settings(&state.db).await?))
}

async fn put_settings(State(state): State<AppState>, Admin(_): Admin, Json(s): Json<Settings>) -> ApiResult<Json<Settings>> {
    if s.trash_days < 0 || s.version_days < 0 || s.keep_latest_versions < 1 {
        return Err(ApiError::bad("invalid retention settings"));
    }
    sqlx::query("INSERT INTO settings (key, value) VALUES ('general', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(serde_json::to_value(&s).unwrap())
        .execute(&state.db)
        .await?;
    Ok(Json(s))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/users", get(list_users).post(create_oidc_user))
        .route("/admin/users/:id", patch(update_user).delete(delete_user))
        .route("/admin/users/:id/reset-2fa", post(reset_2fa))
        .route("/admin/invites", post(create_invite))
        .route("/admin/settings", get(get_settings).put(put_settings))
}
