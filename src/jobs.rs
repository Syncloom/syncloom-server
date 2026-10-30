//! Retention and garbage collection.
use crate::db::get_settings;
use crate::error::ApiResult;
use crate::nodes::purge_node;
use crate::state::AppState;
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct MaintenanceReport {
    pub purged_nodes: usize,
    pub pruned_versions: u64,
    pub deleted_chunks: usize,
}

/// `chunk_grace_secs`: orphaned chunks younger than this are kept (an upload may still be in flight).
pub async fn run_maintenance(state: &AppState, chunk_grace_secs: i64) -> ApiResult<MaintenanceReport> {
    let s = get_settings(&state.db).await?;
    let mut report = MaintenanceReport::default();

    let expired: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM nodes WHERE deleted_at IS NOT NULL AND deleted_at < now() - make_interval(days => $1::int)")
        .bind(s.trash_days as i32)
        .fetch_all(&state.db)
        .await?;
    for id in expired {
        // a parent purge may already have removed this node
        if purge_node(state, id).await.is_ok() {
            report.purged_nodes += 1;
        }
    }

    report.pruned_versions = sqlx::query(
        "DELETE FROM versions WHERE id IN (
             SELECT id FROM (
                 SELECT v.id, v.created_at, n.head_version,
                        row_number() OVER (PARTITION BY v.node_id ORDER BY v.created_at DESC, v.id) AS rn
                 FROM versions v JOIN nodes n ON n.id = v.node_id) t
             WHERE rn > $1 AND created_at < now() - make_interval(days => $2::int) AND id IS DISTINCT FROM head_version)",
    )
    .bind(s.keep_latest_versions)
    .bind(s.version_days as i32)
    .execute(&state.db)
    .await?
    .rows_affected();

    let orphans: Vec<String> = sqlx::query_scalar(
        "DELETE FROM chunks c WHERE NOT EXISTS (SELECT 1 FROM version_chunks vc WHERE vc.hash = c.hash)
           AND c.created_at < now() - make_interval(secs => $1::int) RETURNING c.hash",
    )
    .bind(chunk_grace_secs as i32)
    .fetch_all(&state.db)
    .await?;
    for h in &orphans {
        let _ = state.blobs.delete(h).await;
    }
    report.deleted_chunks = orphans.len();
    Ok(report)
}

pub fn spawn(state: AppState) {
    let every = std::time::Duration::from_secs(state.cfg.maintenance_interval_secs.max(10));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            match run_maintenance(&state, 86_400).await {
                Ok(r) => tracing::info!(?r, "maintenance finished"),
                Err(e) => tracing::warn!("maintenance failed: {e:?}"),
            }
        }
    });
}
