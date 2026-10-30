//! Nodes (files, folders, KV namespaces), versions, chunks, trash and the REST change feed.
use crate::auth::Auth;
use crate::db::{self, access, parse_uuid, record_change, require_write, Access, NODE_COLS};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use sqlx::Row;
use syncloom_core::api::*;
use uuid::Uuid;

pub const MAX_CHUNK_BODY: usize = 2 * 1024 * 1024;

fn valid_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Deserialize)]
struct ListQuery {
    parent: Option<Uuid>,
    #[serde(default)]
    trash: bool,
}

async fn list_nodes(State(state): State<AppState>, Auth(user): Auth, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<NodeDto>>> {
    let rows = if let Some(parent) = q.parent {
        let acc = access(&state.db, user.id, parent).await?;
        let rows = sqlx::query(&format!(
            "SELECT {NODE_COLS} FROM nodes n WHERE n.parent_id = $1 AND n.deleted_at IS NULL ORDER BY n.created_at, n.id"
        ))
        .bind(parent)
        .fetch_all(&state.db)
        .await?;
        rows.iter().map(|r| db::node_from_row(r, acc.as_str())).collect::<ApiResult<Vec<_>>>()?
    } else if q.trash {
        let rows = sqlx::query(&format!(
            "SELECT {NODE_COLS} FROM nodes n WHERE n.owner_id = $1 AND n.deleted_at IS NOT NULL ORDER BY n.deleted_at DESC"
        ))
        .bind(user.id)
        .fetch_all(&state.db)
        .await?;
        rows.iter().map(|r| db::node_from_row(r, "owner")).collect::<ApiResult<Vec<_>>>()?
    } else {
        let rows = sqlx::query(&format!(
            "SELECT {NODE_COLS} FROM nodes n WHERE n.owner_id = $1 AND n.parent_id IS NULL AND n.deleted_at IS NULL ORDER BY n.created_at, n.id"
        ))
        .bind(user.id)
        .fetch_all(&state.db)
        .await?;
        rows.iter().map(|r| db::node_from_row(r, "owner")).collect::<ApiResult<Vec<_>>>()?
    };
    Ok(Json(rows))
}

/// Roots that other users have shared with the caller. `wrapped_key` holds the key sealed to the caller.
async fn shared_with_me(State(state): State<AppState>, Auth(user): Auth) -> ApiResult<Json<Vec<NodeDto>>> {
    let rows = sqlx::query(&format!(
        "SELECT {NODE_COLS}, s.permission, s.sealed_key FROM shares s JOIN nodes n ON n.id = s.node_id
         WHERE s.grantee_id = $1 AND n.deleted_at IS NULL ORDER BY s.created_at"
    ))
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for r in &rows {
        let perm: String = r.try_get("permission")?;
        let mut dto = db::node_from_row(r, &perm)?;
        dto.wrapped_key = r.try_get("sealed_key")?;
        dto.parent_id = None;
        out.push(dto);
    }
    Ok(Json(out))
}

async fn get_node(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<Json<NodeDto>> {
    let acc = access(&state.db, user.id, id).await?;
    Ok(Json(db::fetch_node(&state.db, id, acc.as_str()).await?))
}

async fn create_node(State(state): State<AppState>, Auth(user): Auth, Json(req): Json<CreateNodeReq>) -> ApiResult<(StatusCode, Json<NodeDto>)> {
    let id = parse_uuid(&req.id)?;
    if ![KIND_FILE, KIND_FOLDER, KIND_KV].contains(&req.kind.as_str()) {
        return Err(ApiError::bad("unknown kind"));
    }
    if req.enc_name.len() > 2048 || req.enc_meta.len() > 8192 || req.wrapped_key.is_empty() || req.wrapped_key.len() > 512 {
        return Err(ApiError::bad("field too large"));
    }
    let (owner, parent) = match &req.parent_id {
        Some(p) => {
            let p = parse_uuid(p)?;
            require_write(&state.db, user.id, p).await?;
            let r = sqlx::query("SELECT owner_id, kind, deleted_at FROM nodes WHERE id = $1").bind(p).fetch_one(&state.db).await?;
            let kind: String = r.try_get("kind")?;
            let deleted: Option<chrono::DateTime<chrono::Utc>> = r.try_get("deleted_at")?;
            if kind != KIND_FOLDER || deleted.is_some() {
                return Err(ApiError::bad("parent must be a live folder"));
            }
            (r.try_get::<Uuid, _>("owner_id")?, Some(p))
        }
        None => (user.id, None),
    };
    let mut tx = state.db.begin().await?;
    sqlx::query("INSERT INTO nodes (id, owner_id, parent_id, kind, enc_name, enc_meta, wrapped_key) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(id)
        .bind(owner)
        .bind(parent)
        .bind(&req.kind)
        .bind(&req.enc_name)
        .bind(&req.enc_meta)
        .bind(&req.wrapped_key)
        .execute(&mut *tx)
        .await?;
    let users = record_change(&mut tx, id, "node", None, None).await?;
    tx.commit().await?;
    state.notify_users(&users);
    let acc = if owner == user.id { Access::Owner } else { Access::Rw };
    Ok((StatusCode::CREATED, Json(db::fetch_node(&state.db, id, acc.as_str()).await?)))
}

async fn update_node(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>, Json(req): Json<UpdateNodeReq>) -> ApiResult<Json<NodeDto>> {
    let acc = require_write(&state.db, user.id, id).await?;
    let node = sqlx::query("SELECT owner_id FROM nodes WHERE id = $1").bind(id).fetch_one(&state.db).await?;
    let node_owner: Uuid = node.try_get("owner_id")?;
    let moving = req.parent_id.is_some() || req.to_root;
    if moving && req.wrapped_key.is_none() {
        return Err(ApiError::bad("wrapped_key is required when moving"));
    }
    let mut new_parent: Option<Uuid> = None;
    if let Some(p) = &req.parent_id {
        let p = parse_uuid(p)?;
        require_write(&state.db, user.id, p).await?;
        let r = sqlx::query("SELECT owner_id, kind, deleted_at FROM nodes WHERE id = $1").bind(p).fetch_one(&state.db).await?;
        let kind: String = r.try_get("kind")?;
        let deleted: Option<chrono::DateTime<chrono::Utc>> = r.try_get("deleted_at")?;
        if kind != KIND_FOLDER || deleted.is_some() || r.try_get::<Uuid, _>("owner_id")? != node_owner {
            return Err(ApiError::bad("target must be a live folder of the same owner"));
        }
        let cyc: bool = sqlx::query_scalar(
            "WITH RECURSIVE anc AS (SELECT id, parent_id FROM nodes WHERE id = $1
                 UNION ALL SELECT n.id, n.parent_id FROM nodes n JOIN anc a ON n.id = a.parent_id)
             SELECT EXISTS (SELECT 1 FROM anc WHERE id = $2)",
        )
        .bind(p)
        .bind(id)
        .fetch_one(&state.db)
        .await?;
        if cyc {
            return Err(ApiError::bad("cannot move a folder into itself"));
        }
        new_parent = Some(p);
    } else if req.to_root && acc != Access::Owner {
        return Err(ApiError::Forbidden("only the owner can move to the root".into()));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE nodes SET
            parent_id = CASE WHEN $2 THEN $3 ELSE parent_id END,
            enc_name = COALESCE($4, enc_name), enc_meta = COALESCE($5, enc_meta),
            wrapped_key = COALESCE($6, wrapped_key), updated_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .bind(moving)
    .bind(new_parent)
    .bind(&req.enc_name)
    .bind(&req.enc_meta)
    .bind(&req.wrapped_key)
    .execute(&mut *tx)
    .await?;
    let users = record_change(&mut tx, id, "node", None, None).await?;
    tx.commit().await?;
    state.notify_users(&users);
    Ok(Json(db::fetch_node(&state.db, id, acc.as_str()).await?))
}

async fn trash_node(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    require_write(&state.db, user.id, id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE nodes SET deleted_at = now(), updated_at = now() WHERE id = $1").bind(id).execute(&mut *tx).await?;
    let users = record_change(&mut tx, id, "trash", None, None).await?;
    tx.commit().await?;
    state.notify_users(&users);
    Ok(StatusCode::NO_CONTENT)
}

async fn restore_node(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<Json<NodeDto>> {
    if access(&state.db, user.id, id).await? != Access::Owner {
        return Err(ApiError::Forbidden("only the owner can restore".into()));
    }
    let r = sqlx::query("SELECT parent_id, deleted_at FROM nodes WHERE id = $1").bind(id).fetch_one(&state.db).await?;
    let deleted: Option<chrono::DateTime<chrono::Utc>> = r.try_get("deleted_at")?;
    if deleted.is_none() {
        return Err(ApiError::conflict("node is not in the trash"));
    }
    if let Some(p) = r.try_get::<Option<Uuid>, _>("parent_id")? {
        let parent_deleted: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT deleted_at FROM nodes WHERE id = $1").bind(p).fetch_one(&state.db).await?;
        if parent_deleted.is_some() {
            return Err(ApiError::conflict("parent folder is in the trash"));
        }
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE nodes SET deleted_at = NULL, updated_at = now() WHERE id = $1").bind(id).execute(&mut *tx).await?;
    let users = record_change(&mut tx, id, "restore", None, None).await?;
    tx.commit().await?;
    state.notify_users(&users);
    Ok(Json(db::fetch_node(&state.db, id, "owner").await?))
}

pub async fn purge_node(state: &AppState, id: Uuid) -> ApiResult<()> {
    let mut tx = state.db.begin().await?;
    let users = record_change(&mut tx, id, "purge", None, None).await?;
    sqlx::query("DELETE FROM nodes WHERE id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    state.notify_users(&users);
    Ok(())
}

async fn purge(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    if access(&state.db, user.id, id).await? != Access::Owner {
        return Err(ApiError::Forbidden("only the owner can purge".into()));
    }
    let deleted: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT deleted_at FROM nodes WHERE id = $1").bind(id).fetch_one(&state.db).await?;
    if deleted.is_none() {
        return Err(ApiError::conflict("only trashed items can be purged"));
    }
    purge_node(&state, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- versions ----------

async fn create_version(State(state): State<AppState>, Auth(user): Auth, Path(node_id): Path<Uuid>, Json(req): Json<CreateVersionReq>) -> ApiResult<(StatusCode, Json<VersionDto>)> {
    require_write(&state.db, user.id, node_id).await?;
    let vid = parse_uuid(&req.id)?;
    let base = req.base_version.as_deref().map(parse_uuid).transpose()?;
    if req.size < 0 || req.manifest.len() > 4 * 1024 * 1024 || req.chunks.iter().any(|h| !valid_hash(h)) {
        return Err(ApiError::bad("invalid version"));
    }
    let mut tx = state.db.begin().await?;
    let node = sqlx::query("SELECT owner_id, kind, head_version, deleted_at FROM nodes WHERE id = $1 FOR UPDATE").bind(node_id).fetch_one(&mut *tx).await?;
    let kind: String = node.try_get("kind")?;
    let owner: Uuid = node.try_get("owner_id")?;
    let head: Option<Uuid> = node.try_get("head_version")?;
    let deleted: Option<chrono::DateTime<chrono::Utc>> = node.try_get("deleted_at")?;
    if kind != KIND_FILE || deleted.is_some() {
        return Err(ApiError::bad("not a live file"));
    }
    // idempotent retry of an already-committed request
    if let Some(row) = sqlx::query("SELECT * FROM versions WHERE id = $1 AND node_id = $2").bind(vid).bind(node_id).fetch_optional(&mut *tx).await? {
        drop(tx);
        return Ok((StatusCode::OK, Json(db::version_dto(&state.db, &row).await?)));
    }
    if head != base {
        return Err(ApiError::Conflict(serde_json::to_value(ConflictResp { error: "base version is not the current head".into(), head_version: head.map(|h| h.to_string()) }).unwrap()));
    }
    let distinct: std::collections::HashSet<&String> = req.chunks.iter().collect();
    let distinct: Vec<String> = distinct.into_iter().cloned().collect();
    let present: i64 = sqlx::query_scalar("SELECT count(*) FROM chunks WHERE hash = ANY($1)").bind(&distinct).fetch_one(&mut *tx).await?;
    if present != distinct.len() as i64 {
        return Err(ApiError::bad("some chunks have not been uploaded"));
    }
    let owner_quota: Option<i64> = sqlx::query_scalar("SELECT quota_bytes FROM users WHERE id = $1").bind(owner).fetch_one(&mut *tx).await?;
    if let Some(q) = db::effective_quota(&state.db, owner_quota).await? {
        if db::used_bytes(&mut *tx, owner).await? + req.size > q {
            return Err(ApiError::TooLarge("storage quota exceeded".into()));
        }
    }
    sqlx::query("INSERT INTO versions (id, node_id, parent_version, size, manifest, device) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(vid)
        .bind(node_id)
        .bind(base)
        .bind(req.size)
        .bind(&req.manifest)
        .bind(sqlx::query_scalar::<_, String>("SELECT name FROM tokens WHERE id = $1").bind(user.token_id).fetch_optional(&mut *tx).await?.unwrap_or_default())
        .execute(&mut *tx)
        .await?;
    for (i, h) in req.chunks.iter().enumerate() {
        sqlx::query("INSERT INTO version_chunks (version_id, idx, hash) VALUES ($1,$2,$3)").bind(vid).bind(i as i32).bind(h).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE nodes SET head_version = $2, size = $3, updated_at = now() WHERE id = $1").bind(node_id).bind(vid).bind(req.size).execute(&mut *tx).await?;
    let users = record_change(&mut tx, node_id, "version", Some(vid), None).await?;
    let row = sqlx::query("SELECT * FROM versions WHERE id = $1").bind(vid).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    state.notify_users(&users);
    Ok((StatusCode::CREATED, Json(db::version_dto(&state.db, &row).await?)))
}

async fn list_versions(State(state): State<AppState>, Auth(user): Auth, Path(node_id): Path<Uuid>) -> ApiResult<Json<Vec<VersionDto>>> {
    access(&state.db, user.id, node_id).await?;
    let rows = sqlx::query("SELECT * FROM versions WHERE node_id = $1 ORDER BY created_at DESC, id").bind(node_id).fetch_all(&state.db).await?;
    let mut out = Vec::new();
    for r in &rows {
        out.push(db::version_dto(&state.db, r).await?);
    }
    Ok(Json(out))
}

async fn get_version(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<Json<VersionDto>> {
    let row = sqlx::query("SELECT * FROM versions WHERE id = $1").bind(id).fetch_optional(&state.db).await?.ok_or(ApiError::NotFound)?;
    access(&state.db, user.id, row.try_get("node_id")?).await?;
    Ok(Json(db::version_dto(&state.db, &row).await?))
}

async fn delete_version(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    let row = sqlx::query("SELECT v.node_id, n.head_version FROM versions v JOIN nodes n ON n.id = v.node_id WHERE v.id = $1").bind(id).fetch_optional(&state.db).await?.ok_or(ApiError::NotFound)?;
    let node_id: Uuid = row.try_get("node_id")?;
    if access(&state.db, user.id, node_id).await? != Access::Owner {
        return Err(ApiError::Forbidden("only the owner can delete versions".into()));
    }
    if row.try_get::<Option<Uuid>, _>("head_version")? == Some(id) {
        return Err(ApiError::conflict("cannot delete the current version"));
    }
    sqlx::query("DELETE FROM versions WHERE id = $1").bind(id).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- chunks ----------

async fn missing_chunks(State(state): State<AppState>, Auth(_): Auth, Json(req): Json<MissingChunksReq>) -> ApiResult<Json<MissingChunksResp>> {
    if req.hashes.len() > 10_000 || req.hashes.iter().any(|h| !valid_hash(h)) {
        return Err(ApiError::bad("invalid hashes"));
    }
    let have: Vec<String> = sqlx::query_scalar("SELECT hash FROM chunks WHERE hash = ANY($1)").bind(&req.hashes).fetch_all(&state.db).await?;
    let have: std::collections::HashSet<_> = have.into_iter().collect();
    Ok(Json(MissingChunksResp { missing: req.hashes.into_iter().filter(|h| !have.contains(h)).collect() }))
}

async fn put_chunk(State(state): State<AppState>, Auth(user): Auth, Path(hash): Path<String>, body: Bytes) -> ApiResult<StatusCode> {
    if !valid_hash(&hash) {
        return Err(ApiError::bad("invalid hash"));
    }
    if body.len() > MAX_CHUNK_BODY || body.is_empty() {
        return Err(ApiError::bad("bad chunk size"));
    }
    if blake3::hash(&body).to_hex().as_str() != hash {
        return Err(ApiError::bad("hash does not match content"));
    }
    let r = sqlx::query("INSERT INTO chunks (hash, size, uploaded_by) VALUES ($1, $2, $3) ON CONFLICT (hash) DO NOTHING")
        .bind(&hash)
        .bind(body.len() as i64)
        .bind(user.id)
        .execute(&state.db)
        .await?;
    if r.rows_affected() == 1 {
        // blob first would risk an orphan row pointing at nothing; keep row+blob consistent on failure
        if let Err(e) = state.blobs.put(&hash, body).await {
            let _ = sqlx::query("DELETE FROM chunks WHERE hash = $1").bind(&hash).execute(&state.db).await;
            return Err(e);
        }
        Ok(StatusCode::CREATED)
    } else {
        Ok(StatusCode::OK)
    }
}

async fn get_chunk(State(state): State<AppState>, Auth(user): Auth, Path(hash): Path<String>) -> ApiResult<Response> {
    if !valid_hash(&hash) {
        return Err(ApiError::bad("invalid hash"));
    }
    let nodes: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT v.node_id FROM version_chunks vc JOIN versions v ON v.id = vc.version_id
         JOIN nodes n ON n.id = v.node_id WHERE vc.hash = $1 LIMIT 50",
    )
    .bind(&hash)
    .fetch_all(&state.db)
    .await?;
    let mut allowed = false;
    for n in nodes {
        if access(&state.db, user.id, n).await.is_ok() {
            allowed = true;
            break;
        }
    }
    if !allowed {
        return Err(ApiError::NotFound);
    }
    chunk_response(&state, &hash).await
}

pub async fn chunk_response(state: &AppState, hash: &str) -> ApiResult<Response> {
    let data = state.blobs.get(hash).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream"), (header::CACHE_CONTROL, "private, max-age=31536000, immutable")], data).into_response())
}

// ---------- change feed (REST) ----------

#[derive(Deserialize)]
struct ChangesQuery {
    #[serde(default)]
    since: i64,
    limit: Option<i64>,
}

pub async fn fetch_changes(db: &sqlx::PgPool, user: Uuid, since: i64, limit: i64) -> ApiResult<Vec<ChangeDto>> {
    let rows = sqlx::query("SELECT cursor, node_id, kind, version_id, kv_key FROM changes WHERE user_id = $1 AND cursor > $2 ORDER BY cursor LIMIT $3")
        .bind(user)
        .bind(since)
        .bind(limit)
        .fetch_all(db)
        .await?;
    rows.iter()
        .map(|r| {
            Ok(ChangeDto {
                cursor: r.try_get("cursor")?,
                node_id: r.try_get::<Uuid, _>("node_id")?.to_string(),
                kind: r.try_get("kind")?,
                version_id: r.try_get::<Option<Uuid>, _>("version_id")?.map(|v| v.to_string()),
                kv_key: r.try_get("kv_key")?,
            })
        })
        .collect()
}

async fn changes(State(state): State<AppState>, Auth(user): Auth, Query(q): Query<ChangesQuery>) -> ApiResult<Json<ChangesResp>> {
    let list = fetch_changes(&state.db, user.id, q.since, q.limit.unwrap_or(500).clamp(1, 5000)).await?;
    let next = list.last().map(|c| c.cursor).unwrap_or(q.since);
    Ok(Json(ChangesResp { changes: list, next_cursor: next }))
}

/// Current head cursor, used as the baseline after a full tree walk.
async fn changes_head(State(state): State<AppState>, Auth(user): Auth) -> ApiResult<Json<ChangesResp>> {
    let c: Option<i64> = sqlx::query_scalar("SELECT max(cursor) FROM changes WHERE user_id = $1").bind(user.id).fetch_one(&state.db).await?;
    Ok(Json(ChangesResp { changes: vec![], next_cursor: c.unwrap_or(0) }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/nodes", get(list_nodes).post(create_node))
        .route("/shared", get(shared_with_me))
        .route("/nodes/:id", get(get_node).patch(update_node).delete(trash_node))
        .route("/nodes/:id/restore", post(restore_node))
        .route("/trash/:id", delete(purge))
        .route("/nodes/:id/versions", get(list_versions).post(create_version))
        .route("/versions/:id", get(get_version).delete(delete_version))
        .route("/chunks/missing", post(missing_chunks))
        .route("/chunks/:hash", put(put_chunk).get(get_chunk))
        .route("/changes", get(changes))
        .route("/changes/head", get(changes_head))
}
