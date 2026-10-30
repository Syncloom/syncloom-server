//! Syncloom server: accounts, encrypted file and key/value storage, sharing, change feed.
pub mod admin;
pub mod auth;
pub mod blobs;
pub mod changes;
pub mod config;
pub mod db;
pub mod error;
pub mod jobs;
pub mod kv;
pub mod nodes;
pub mod oidc;
pub mod shares;
pub mod state;

use axum::{extract::DefaultBodyLimit, http::HeaderValue, routing::get, Router};
use rand::RngCore;
use sqlx::postgres::PgPoolOptions;
use state::{AppState, Inner};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use syncloom_core::grpc::sync_server::SyncServer;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use webauthn_rs::prelude::{Url, WebauthnBuilder};

pub async fn build_state(cfg: config::Config) -> Result<AppState, String> {
    let pool = PgPoolOptions::new().max_connections(20).connect(&cfg.database_url).await.map_err(|e| format!("database: {e}"))?;
    db::migrate(&pool).await.map_err(|e| format!("migrations: {e}"))?;
    let blobs = blobs::Blobs::new(&cfg.blobs)?;

    // persistent random secret (only used to make prelogin answers for unknown users stable)
    let mut secret = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    sqlx::query("INSERT INTO settings (key, value) VALUES ('server_secret', to_jsonb($1::text)) ON CONFLICT (key) DO NOTHING")
        .bind(hex::encode(&secret))
        .execute(&pool)
        .await
        .map_err(|e| e.to_string())?;
    let stored: serde_json::Value = sqlx::query_scalar("SELECT value FROM settings WHERE key = 'server_secret'").fetch_one(&pool).await.map_err(|e| e.to_string())?;
    let secret = hex::decode(stored.as_str().unwrap_or_default()).map_err(|e| e.to_string())?;

    let webauthn = {
        let url = Url::parse(&cfg.public_url).map_err(|e| format!("PUBLIC_URL: {e}"))?;
        let rp_id = url.host_str().ok_or("PUBLIC_URL has no host")?.to_string();
        Some(WebauthnBuilder::new(&rp_id, &url).and_then(|b| b.rp_name("Syncloom").danger_set_user_presence_only_security_keys(true).build()).map_err(|e| format!("webauthn: {e}"))?)
    };
    let (notify, _) = tokio::sync::broadcast::channel(1024);
    Ok(Arc::new(Inner {
        db: pool,
        cfg,
        blobs,
        notify,
        webauthn,
        wa_reg: Mutex::new(HashMap::new()),
        wa_auth: Mutex::new(HashMap::new()),
        oidc_pending: Mutex::new(HashMap::new()),
        login_attempts: Mutex::new(HashMap::new()),
        server_secret: secret,
    }))
}

pub fn app(state: AppState) -> Router {
    let api = Router::new()
        .merge(auth::routes())
        .merge(nodes::routes())
        .merge(kv::routes())
        .merge(shares::routes())
        .merge(admin::routes())
        .merge(oidc::routes())
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(state.clone());

    let grpc = tonic_web::enable(SyncServer::new(changes::SyncSvc { state: state.clone() }));
    let grpc = tonic::service::Routes::new(grpc).into_axum_router();

    let mut router = Router::new().route("/health", get(|| async { "ok" })).nest("/api/v1", api).merge(grpc);
    if !state.cfg.cors_origins.is_empty() {
        let origins: Vec<HeaderValue> = state.cfg.cors_origins.iter().filter_map(|o| o.parse().ok()).collect();
        router = router.layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any)
                .expose_headers([axum::http::HeaderName::from_static("grpc-status"), axum::http::HeaderName::from_static("grpc-message")]),
        );
    }
    router.layer(TraceLayer::new_for_http())
}
