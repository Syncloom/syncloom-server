//! User shares (key wrapped to the grantee), public links, and the unauthenticated link endpoints.
use crate::auth::{hash_secret, hash_token, new_token, verify_secret, Auth};
use crate::db::{self, access, parse_uuid, record_user_change, Access, NODE_COLS};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use sqlx::Row;
use syncloom_core::api::*;
use uuid::Uuid;

async fn owner_only(state: &AppState, user: Uuid, node: Uuid) -> ApiResult<()> {
    if access(&state.db, user, node).await? != Access::Owner {
        return Err(ApiError::Forbidden("only the owner can manage sharing".into()));
    }
    Ok(())
}

async fn create_share(State(state): State<AppState>, Auth(user): Auth, Json(req): Json<CreateShareReq>) -> ApiResult<(StatusCode, Json<ShareDto>)> {
    let node = parse_uuid(&req.node_id)?;
    owner_only(&state, user.id, node).await?;
    if !["rw", "ro"].contains(&req.permission.as_str()) {
        return Err(ApiError::bad("permission must be rw or ro"));
    }
    if req.sealed_key.is_empty() || req.sealed_key.len() > 512 {
        return Err(ApiError::bad("invalid sealed key"));
    }
    let grantee: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND disabled = false")
        .bind(req.grantee.to_lowercase())
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::bad("unknown user"))?;
    if grantee == user.id {
        return Err(ApiError::bad("cannot share with yourself"));
    }
    let id = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    let row = sqlx::query(
        "INSERT INTO shares (id, node_id, grantee_id, permission, sealed_key, created_by) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (node_id, grantee_id) DO UPDATE SET permission = EXCLUDED.permission, sealed_key = EXCLUDED.sealed_key
         RETURNING id",
    )
    .bind(id)
    .bind(node)
    .bind(grantee)
    .bind(&req.permission)
    .bind(&req.sealed_key)
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;
    record_user_change(&mut tx, grantee, node, "share").await?;
    tx.commit().await?;
    state.notify_users(&[grantee]);
    let id: Uuid = row.try_get("id")?;
    Ok((StatusCode::CREATED, Json(ShareDto { id: id.to_string(), node_id: node.to_string(), grantee: req.grantee.to_lowercase(), permission: req.permission })))
}

#[derive(Deserialize)]
struct NodeQuery {
    node_id: Uuid,
}

async fn list_shares(State(state): State<AppState>, Auth(user): Auth, Query(q): Query<NodeQuery>) -> ApiResult<Json<Vec<ShareDto>>> {
    owner_only(&state, user.id, q.node_id).await?;
    let rows = sqlx::query("SELECT s.id, s.node_id, s.permission, u.username FROM shares s JOIN users u ON u.id = s.grantee_id WHERE s.node_id = $1 ORDER BY s.created_at")
        .bind(q.node_id)
        .fetch_all(&state.db)
        .await?;
    rows.iter()
        .map(|r| Ok(ShareDto { id: r.try_get::<Uuid, _>("id")?.to_string(), node_id: r.try_get::<Uuid, _>("node_id")?.to_string(), grantee: r.try_get("username")?, permission: r.try_get("permission")? }))
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

async fn delete_share(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    let r = sqlx::query("SELECT node_id, grantee_id FROM shares WHERE id = $1").bind(id).fetch_optional(&state.db).await?.ok_or(ApiError::NotFound)?;
    let node: Uuid = r.try_get("node_id")?;
    let grantee: Uuid = r.try_get("grantee_id")?;
    // the owner revokes; the grantee may leave a share
    if grantee != user.id {
        owner_only(&state, user.id, node).await?;
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM shares WHERE id = $1").bind(id).execute(&mut *tx).await?;
    record_user_change(&mut tx, grantee, node, "share").await?;
    tx.commit().await?;
    state.notify_users(&[grantee]);
    Ok(StatusCode::NO_CONTENT)
}

// ---------- links ----------

async fn create_link(State(state): State<AppState>, Auth(user): Auth, Json(req): Json<CreateLinkReq>) -> ApiResult<(StatusCode, Json<CreateLinkResp>)> {
    let node = parse_uuid(&req.node_id)?;
    owner_only(&state, user.id, node).await?;
    if req.key_envelope.is_empty() || req.key_envelope.len() > 512 {
        return Err(ApiError::bad("invalid key envelope"));
    }
    let pw_hash = match req.password.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => Some(hash_secret(p.to_string()).await?),
        None => None,
    };
    let id = Uuid::new_v4();
    let token = new_token();
    sqlx::query(
        "INSERT INTO links (id, node_id, token_hash, password_hash, expires_at, max_downloads, key_envelope, created_by)
         VALUES ($1,$2,$3,$4, CASE WHEN $5::bigint IS NULL THEN NULL ELSE to_timestamp($5::bigint / 1000.0) END, $6,$7,$8)",
    )
    .bind(id)
    .bind(node)
    .bind(hash_token(&token))
    .bind(pw_hash)
    .bind(req.expires_at)
    .bind(req.max_downloads)
    .bind(&req.key_envelope)
    .bind(user.id)
    .execute(&state.db)
    .await?;
    Ok((StatusCode::CREATED, Json(CreateLinkResp { id: id.to_string(), token })))
}

async fn list_links(State(state): State<AppState>, Auth(user): Auth, Query(q): Query<NodeQuery>) -> ApiResult<Json<Vec<LinkDto>>> {
    owner_only(&state, user.id, q.node_id).await?;
    let rows = sqlx::query("SELECT id, node_id, password_hash IS NOT NULL AS has_pw, expires_at, max_downloads, downloads FROM links WHERE node_id = $1 ORDER BY created_at")
        .bind(q.node_id)
        .fetch_all(&state.db)
        .await?;
    rows.iter()
        .map(|r| {
            let exp: Option<chrono::DateTime<chrono::Utc>> = r.try_get("expires_at")?;
            Ok(LinkDto {
                id: r.try_get::<Uuid, _>("id")?.to_string(),
                node_id: r.try_get::<Uuid, _>("node_id")?.to_string(),
                has_password: r.try_get("has_pw")?,
                expires_at: exp.map(|e| e.timestamp_millis()),
                max_downloads: r.try_get("max_downloads")?,
                downloads: r.try_get("downloads")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

async fn delete_link(State(state): State<AppState>, Auth(user): Auth, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    let node: Uuid = sqlx::query_scalar("SELECT node_id FROM links WHERE id = $1").bind(id).fetch_optional(&state.db).await?.ok_or(ApiError::NotFound)?;
    owner_only(&state, user.id, node).await?;
    sqlx::query("DELETE FROM links WHERE id = $1").bind(id).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- public (unauthenticated) ----------

struct LinkCtx {
    id: Uuid,
    node: Uuid,
    envelope: Vec<u8>,
    max_downloads: Option<i64>,
    downloads: i64,
}

/// Validates token, expiry and password. Does not count a download.
async fn link_ctx(state: &AppState, token: &str, headers: &HeaderMap) -> ApiResult<LinkCtx> {
    let r = sqlx::query(
        "SELECT l.id, l.node_id, l.password_hash, l.key_envelope, l.max_downloads, l.downloads,
                (l.expires_at IS NOT NULL AND l.expires_at < now()) AS expired, n.deleted_at
         FROM links l JOIN nodes n ON n.id = l.node_id WHERE l.token_hash = $1",
    )
    .bind(hash_token(token))
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let deleted: Option<chrono::DateTime<chrono::Utc>> = r.try_get("deleted_at")?;
    if r.try_get::<bool, _>("expired")? || deleted.is_some() {
        return Err(ApiError::NotFound);
    }
    if let Some(hash) = r.try_get::<Option<String>, _>("password_hash")? {
        let key = format!("link:{}", r.try_get::<Uuid, _>("id")?);
        if !state.check_login_allowed(&key) {
            return Err(ApiError::TooManyRequests("too many attempts".into()));
        }
        let given = headers.get("x-link-password").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        if !verify_secret(given, hash).await {
            state.record_login_failure(&key);
            return Err(ApiError::Unauthorized("password required".into()));
        }
    }
    Ok(LinkCtx {
        id: r.try_get("id")?,
        node: r.try_get("node_id")?,
        envelope: r.try_get("key_envelope")?,
        max_downloads: r.try_get("max_downloads")?,
        downloads: r.try_get("downloads")?,
    })
}

async fn in_subtree(state: &AppState, root: Uuid, node: Uuid) -> ApiResult<bool> {
    Ok(sqlx::query_scalar(
        "WITH RECURSIVE anc AS (SELECT id, parent_id FROM nodes WHERE id = $1
             UNION ALL SELECT n.id, n.parent_id FROM nodes n JOIN anc a ON n.id = a.parent_id)
         SELECT EXISTS (SELECT 1 FROM anc WHERE id = $2)",
    )
    .bind(node)
    .bind(root)
    .fetch_one(&state.db)
    .await?)
}

async fn public_link(State(state): State<AppState>, Path(token): Path<String>, headers: HeaderMap) -> ApiResult<Json<PublicLinkResp>> {
    let ctx = link_ctx(&state, &token, &headers).await?;
    let mut node = db::fetch_node(&state.db, ctx.node, "ro").await?;
    node.parent_id = None;
    Ok(Json(PublicLinkResp { node, key_envelope: ctx.envelope }))
}

#[derive(Deserialize)]
struct ParentQuery {
    parent: Option<Uuid>,
}

async fn public_nodes(State(state): State<AppState>, Path(token): Path<String>, Query(q): Query<ParentQuery>, headers: HeaderMap) -> ApiResult<Json<Vec<NodeDto>>> {
    let ctx = link_ctx(&state, &token, &headers).await?;
    let parent = q.parent.unwrap_or(ctx.node);
    if !in_subtree(&state, ctx.node, parent).await? {
        return Err(ApiError::NotFound);
    }
    let rows = sqlx::query(&format!("SELECT {NODE_COLS} FROM nodes n WHERE n.parent_id = $1 AND n.deleted_at IS NULL ORDER BY n.created_at, n.id")).bind(parent).fetch_all(&state.db).await?;
    rows.iter().map(|r| db::node_from_row(r, "ro")).collect::<ApiResult<Vec<_>>>().map(Json)
}

/// Head version of a file in the link's subtree. This counts as one download.
async fn public_version(State(state): State<AppState>, Path((token, node_id)): Path<(String, Uuid)>, headers: HeaderMap) -> ApiResult<Json<VersionDto>> {
    let ctx = link_ctx(&state, &token, &headers).await?;
    if !in_subtree(&state, ctx.node, node_id).await? {
        return Err(ApiError::NotFound);
    }
    let row = sqlx::query("SELECT v.* FROM nodes n JOIN versions v ON v.id = n.head_version WHERE n.id = $1 AND n.deleted_at IS NULL").bind(node_id).fetch_optional(&state.db).await?.ok_or(ApiError::NotFound)?;
    if let Some(max) = ctx.max_downloads {
        if ctx.downloads >= max {
            return Err(ApiError::Forbidden("download limit reached".into()));
        }
    }
    let updated = sqlx::query("UPDATE links SET downloads = downloads + 1 WHERE id = $1 AND (max_downloads IS NULL OR downloads < max_downloads)").bind(ctx.id).execute(&state.db).await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::Forbidden("download limit reached".into()));
    }
    Ok(Json(db::version_dto(&state.db, &row).await?))
}

async fn public_chunk(State(state): State<AppState>, Path((token, hash)): Path<(String, String)>, headers: HeaderMap) -> ApiResult<Response> {
    let ctx = link_ctx(&state, &token, &headers).await?;
    let ok: bool = sqlx::query_scalar(
        "WITH RECURSIVE sub AS (SELECT id FROM nodes WHERE id = $1
             UNION ALL SELECT n.id FROM nodes n JOIN sub ON n.parent_id = sub.id)
         SELECT EXISTS (SELECT 1 FROM version_chunks vc JOIN versions v ON v.id = vc.version_id
                        WHERE vc.hash = $2 AND v.node_id IN (SELECT id FROM sub))",
    )
    .bind(ctx.node)
    .bind(&hash)
    .fetch_one(&state.db)
    .await?;
    if !ok {
        return Err(ApiError::NotFound);
    }
    crate::nodes::chunk_response(&state, &hash).await
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/shares", post(create_share).get(list_shares))
        .route("/shares/:id", delete(delete_share))
        .route("/links", post(create_link).get(list_links))
        .route("/links/:id", delete(delete_link))
        .route("/public/:token", get(public_link))
        .route("/public/:token/nodes", get(public_nodes))
        .route("/public/:token/versions/:node_id", get(public_version))
        .route("/public/:token/chunks/:hash", get(public_chunk))
}
