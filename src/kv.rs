//! Key/value namespaces. A namespace is a node of kind `kv`, so sharing, trash, quotas and the
//! change feed work exactly like for files. Values are opaque ciphertext.
use crate::auth::Auth;
use crate::db::{access, record_change, require_write};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use sqlx::Row;
use syncloom_core::api::*;
use uuid::Uuid;

async fn ensure_ns(state: &AppState, ns: Uuid) -> ApiResult<()> {
    let r = sqlx::query("SELECT kind, deleted_at FROM nodes WHERE id = $1").bind(ns).fetch_optional(&state.db).await?.ok_or(ApiError::NotFound)?;
    let kind: String = r.try_get("kind")?;
    let deleted: Option<chrono::DateTime<chrono::Utc>> = r.try_get("deleted_at")?;
    if kind != KIND_KV || deleted.is_some() {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

fn validate_key(key: &str) -> ApiResult<()> {
    if key.is_empty() || key.len() > 512 || key.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad("invalid key"));
    }
    Ok(())
}

fn entry_from_row(r: &sqlx::postgres::PgRow) -> ApiResult<KvEntryDto> {
    let updated: chrono::DateTime<chrono::Utc> = r.try_get("updated_at")?;
    Ok(KvEntryDto { key: r.try_get("key")?, value: r.try_get("value")?, version: r.try_get("version")?, deleted: r.try_get("deleted")?, updated_at: updated.timestamp_millis() })
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    include_deleted: bool,
    limit: Option<i64>,
}

async fn list(State(state): State<AppState>, Auth(user): Auth, Path(ns): Path<Uuid>, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<KvEntryDto>>> {
    access(&state.db, user.id, ns).await?;
    ensure_ns(&state, ns).await?;
    let like = format!("{}%", q.prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let rows = sqlx::query("SELECT key, value, version, deleted, updated_at FROM kv_entries WHERE ns_id = $1 AND key LIKE $2 AND ($3 OR NOT deleted) ORDER BY key LIMIT $4")
        .bind(ns)
        .bind(like)
        .bind(q.include_deleted)
        .bind(q.limit.unwrap_or(1000).clamp(1, 10_000))
        .fetch_all(&state.db)
        .await?;
    rows.iter().map(entry_from_row).collect::<ApiResult<Vec<_>>>().map(Json)
}

async fn get_entry(State(state): State<AppState>, Auth(user): Auth, Path((ns, key)): Path<(Uuid, String)>) -> ApiResult<Json<KvEntryDto>> {
    access(&state.db, user.id, ns).await?;
    ensure_ns(&state, ns).await?;
    let r = sqlx::query("SELECT key, value, version, deleted, updated_at FROM kv_entries WHERE ns_id = $1 AND key = $2 AND NOT deleted")
        .bind(ns)
        .bind(&key)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(entry_from_row(&r)?))
}

enum Write {
    Put(Vec<u8>),
    Delete,
}

async fn write_entry(state: &AppState, user: Uuid, ns: Uuid, key: &str, w: Write, if_version: Option<i64>) -> ApiResult<KvEntryDto> {
    validate_key(key)?;
    require_write(&state.db, user, ns).await?;
    ensure_ns(state, ns).await?;
    let mut tx = state.db.begin().await?;
    // serialize writers on the namespace row, which also guards creation races for new keys
    sqlx::query("SELECT 1 FROM nodes WHERE id = $1 FOR UPDATE").bind(ns).execute(&mut *tx).await?;
    let cur = sqlx::query("SELECT key, value, version, deleted, updated_at FROM kv_entries WHERE ns_id = $1 AND key = $2").bind(ns).bind(key).fetch_optional(&mut *tx).await?;
    let (cur_version, live) = match &cur {
        Some(r) => (r.try_get::<i64, _>("version")?, !r.try_get::<bool, _>("deleted")?),
        None => (0, false),
    };
    if let Some(expected) = if_version {
        let observed = if live { cur_version } else { 0 };
        if observed != expected {
            let current = match &cur {
                Some(r) if live => Some(entry_from_row(r)?),
                _ => None,
            };
            return Err(ApiError::Conflict(serde_json::to_value(KvConflictResp { error: "version mismatch".into(), current }).unwrap()));
        }
    }
    let (value, deleted) = match w {
        Write::Put(v) => (v, false),
        Write::Delete => (Vec::new(), true),
    };
    if deleted && !live {
        return Err(ApiError::NotFound);
    }
    let row = sqlx::query(
        "INSERT INTO kv_entries (ns_id, key, value, version, deleted, updated_at) VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (ns_id, key) DO UPDATE SET value = EXCLUDED.value, version = EXCLUDED.version, deleted = EXCLUDED.deleted, updated_at = now()
         RETURNING key, value, version, deleted, updated_at",
    )
    .bind(ns)
    .bind(key)
    .bind(&value)
    .bind(cur_version + 1)
    .bind(deleted)
    .fetch_one(&mut *tx)
    .await?;
    let users = record_change(&mut tx, ns, "kv", None, Some(key)).await?;
    tx.commit().await?;
    state.notify_users(&users);
    entry_from_row(&row)
}

async fn put_entry(State(state): State<AppState>, Auth(user): Auth, Path((ns, key)): Path<(Uuid, String)>, Json(req): Json<KvPutReq>) -> ApiResult<Json<KvEntryDto>> {
    if req.value.len() > KV_MAX_VALUE + 64 {
        return Err(ApiError::TooLarge(format!("value exceeds {KV_MAX_VALUE} bytes")));
    }
    Ok(Json(write_entry(&state, user.id, ns, &key, Write::Put(req.value), req.if_version).await?))
}

#[derive(Deserialize)]
struct DeleteQuery {
    if_version: Option<i64>,
}

async fn delete_entry(State(state): State<AppState>, Auth(user): Auth, Path((ns, key)): Path<(Uuid, String)>, Query(q): Query<DeleteQuery>) -> ApiResult<StatusCode> {
    write_entry(&state, user.id, ns, &key, Write::Delete, q.if_version).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/kv/:ns/list", get(list)).route("/kv/:ns/e/*key", get(get_entry).put(put_entry).delete(delete_entry))
}
