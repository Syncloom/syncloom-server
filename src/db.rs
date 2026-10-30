//! Shared query helpers: access checks, change recording, quota, DTO mapping.
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use sqlx::{postgres::PgRow, PgConnection, PgPool, Row};
use syncloom_core::api::{NodeDto, Settings, VersionDto};
use uuid::Uuid;

pub async fn migrate(db: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(db).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Ro,
    Rw,
    Owner,
}

impl Access {
    pub fn can_write(self) -> bool {
        matches!(self, Access::Rw | Access::Owner)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Ro => "ro",
            Access::Rw => "rw",
            Access::Owner => "owner",
        }
    }
}

/// What `user` may do with `node`. `NotFound` if nothing (so existence is not leaked).
pub async fn access(db: impl sqlx::PgExecutor<'_>, user: Uuid, node: Uuid) -> ApiResult<Access> {
    let row = sqlx::query(
        "WITH RECURSIVE anc AS (
             SELECT id, parent_id, deleted_at FROM nodes WHERE id = $2
             UNION ALL
             SELECT n.id, n.parent_id, n.deleted_at FROM nodes n JOIN anc a ON n.id = a.parent_id)
         SELECT (SELECT owner_id FROM nodes WHERE id = $2) AS owner,
                (SELECT permission FROM shares s WHERE s.grantee_id = $1 AND s.node_id IN (SELECT id FROM anc)
                   ORDER BY (permission = 'rw') DESC LIMIT 1) AS perm,
                (SELECT bool_or(deleted_at IS NOT NULL) FROM anc) AS trashed",
    )
    .bind(user)
    .bind(node)
    .fetch_one(db)
    .await?;
    let owner: Option<Uuid> = row.try_get("owner")?;
    let perm: Option<String> = row.try_get("perm")?;
    let trashed: Option<bool> = row.try_get("trashed")?;
    match owner {
        None => Err(ApiError::NotFound),
        Some(o) if o == user => Ok(Access::Owner),
        Some(_) => match perm.as_deref() {
            Some(_) if trashed == Some(true) => Err(ApiError::NotFound),
            Some("rw") => Ok(Access::Rw),
            Some(_) => Ok(Access::Ro),
            None => Err(ApiError::NotFound),
        },
    }
}

pub async fn require_write(db: impl sqlx::PgExecutor<'_>, user: Uuid, node: Uuid) -> ApiResult<Access> {
    let a = access(db, user, node).await?;
    if a.can_write() {
        Ok(a)
    } else {
        Err(ApiError::Forbidden("read-only access".into()))
    }
}

/// Record a change for the owner and every user that has a share on the node or an ancestor.
/// Returns the interested users so the caller can notify after commit.
pub async fn record_change(
    conn: &mut PgConnection,
    node: Uuid,
    kind: &str,
    version: Option<Uuid>,
    kv_key: Option<&str>,
) -> ApiResult<Vec<Uuid>> {
    let rows = sqlx::query(
        "WITH RECURSIVE anc AS (
             SELECT id, parent_id, owner_id FROM nodes WHERE id = $1
             UNION ALL
             SELECT n.id, n.parent_id, n.owner_id FROM nodes n JOIN anc a ON n.id = a.parent_id),
         interested AS (
             SELECT owner_id AS uid FROM anc WHERE id = $1
             UNION SELECT grantee_id FROM shares WHERE node_id IN (SELECT id FROM anc))
         INSERT INTO changes (user_id, node_id, kind, version_id, kv_key)
         SELECT uid, $1, $2, $3, $4 FROM interested
         RETURNING user_id",
    )
    .bind(node)
    .bind(kind)
    .bind(version)
    .bind(kv_key)
    .fetch_all(conn)
    .await?;
    rows.iter().map(|r| Ok(r.try_get("user_id")?)).collect()
}

pub async fn record_user_change(conn: &mut PgConnection, user: Uuid, node: Uuid, kind: &str) -> ApiResult<()> {
    sqlx::query("INSERT INTO changes (user_id, node_id, kind) VALUES ($1, $2, $3)")
        .bind(user)
        .bind(node)
        .bind(kind)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn used_bytes(db: impl sqlx::PgExecutor<'_>, owner: Uuid) -> ApiResult<i64> {
    let used: Option<i64> = sqlx::query_scalar(
        "SELECT SUM(v.size)::bigint FROM versions v JOIN nodes n ON n.id = v.node_id WHERE n.owner_id = $1",
    )
    .bind(owner)
    .fetch_one(db)
    .await?;
    Ok(used.unwrap_or(0))
}

pub async fn get_settings(db: impl sqlx::PgExecutor<'_>) -> ApiResult<Settings> {
    let v: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM settings WHERE key = 'general'").fetch_optional(db).await?;
    Ok(v.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default())
}

pub async fn effective_quota(db: &PgPool, user_quota: Option<i64>) -> ApiResult<Option<i64>> {
    match user_quota {
        Some(q) => Ok(Some(q)),
        None => Ok(get_settings(db).await?.default_quota_bytes),
    }
}

pub const NODE_COLS: &str = "n.id, n.parent_id, n.owner_id, n.kind, n.enc_name, n.enc_meta, n.wrapped_key, \
                             n.head_version, n.size, n.deleted_at, n.updated_at";

pub fn node_from_row(r: &PgRow, access: &str) -> ApiResult<NodeDto> {
    let id: Uuid = r.try_get("id")?;
    let parent: Option<Uuid> = r.try_get("parent_id")?;
    let owner: Uuid = r.try_get("owner_id")?;
    let head: Option<Uuid> = r.try_get("head_version")?;
    let deleted: Option<chrono::DateTime<chrono::Utc>> = r.try_get("deleted_at")?;
    let updated: chrono::DateTime<chrono::Utc> = r.try_get("updated_at")?;
    Ok(NodeDto {
        id: id.to_string(),
        parent_id: parent.map(|p| p.to_string()),
        owner_id: owner.to_string(),
        kind: r.try_get("kind")?,
        enc_name: r.try_get("enc_name")?,
        enc_meta: r.try_get("enc_meta")?,
        wrapped_key: r.try_get("wrapped_key")?,
        head_version: head.map(|h| h.to_string()),
        size: r.try_get("size")?,
        deleted: deleted.is_some(),
        updated_at: updated.timestamp_millis(),
        access: access.to_string(),
    })
}

pub async fn fetch_node(db: impl sqlx::PgExecutor<'_>, id: Uuid, access: &str) -> ApiResult<NodeDto> {
    let row = sqlx::query(&format!("SELECT {NODE_COLS} FROM nodes n WHERE n.id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or(ApiError::NotFound)?;
    node_from_row(&row, access)
}

pub async fn version_dto(db: &PgPool, row: &PgRow) -> ApiResult<VersionDto> {
    let id: Uuid = row.try_get("id")?;
    let node_id: Uuid = row.try_get("node_id")?;
    let parent: Option<Uuid> = row.try_get("parent_version")?;
    let created: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;
    let chunks: Vec<String> =
        sqlx::query_scalar("SELECT hash FROM version_chunks WHERE version_id = $1 ORDER BY idx").bind(id).fetch_all(db).await?;
    Ok(VersionDto {
        id: id.to_string(),
        node_id: node_id.to_string(),
        parent_version: parent.map(|p| p.to_string()),
        size: row.try_get("size")?,
        manifest: row.try_get("manifest")?,
        chunks,
        created_at: created.timestamp_millis(),
        device: row.try_get("device")?,
    })
}

pub fn parse_uuid(s: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(s).map_err(|_| ApiError::bad("invalid id"))
}

/// Run `f` and notify interested users after the DB transaction has committed.
pub fn notify_after_commit(state: &AppState, users: &[Uuid]) {
    state.notify_users(users);
}
