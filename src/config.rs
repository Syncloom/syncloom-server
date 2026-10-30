use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum BlobBackend {
    Fs(PathBuf),
    S3 { bucket: String, region: String, endpoint: Option<String>, access_key: Option<String>, secret_key: Option<String> },
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub auto_provision: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub listen_addr: String,
    /// Externally visible base URL (used for WebAuthn RP id/origin and OIDC redirects).
    pub public_url: String,
    pub blobs: BlobBackend,
    pub oidc: Option<OidcConfig>,
    /// Allow username/password (+ mandatory 2FA) accounts.
    pub local_auth: bool,
    /// Allowed browser origins for cross-origin dev setups (comma-separated). Empty = same-origin only.
    pub cors_origins: Vec<String>,
    pub maintenance_interval_secs: u64,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let database_url = env("DATABASE_URL").ok_or("DATABASE_URL is required")?;
        let blobs = match env("BLOB_BACKEND").as_deref().unwrap_or("fs") {
            "fs" => BlobBackend::Fs(env("BLOB_PATH").unwrap_or_else(|| "./data/blobs".into()).into()),
            "s3" => BlobBackend::S3 {
                bucket: env("S3_BUCKET").ok_or("S3_BUCKET is required for BLOB_BACKEND=s3")?,
                region: env("S3_REGION").unwrap_or_else(|| "us-east-1".into()),
                endpoint: env("S3_ENDPOINT"),
                access_key: env("S3_ACCESS_KEY"),
                secret_key: env("S3_SECRET_KEY"),
            },
            other => return Err(format!("unknown BLOB_BACKEND {other}")),
        };
        let oidc = match (env("OIDC_ISSUER"), env("OIDC_CLIENT_ID")) {
            (Some(issuer), Some(client_id)) => Some(OidcConfig {
                issuer,
                client_id,
                client_secret: env("OIDC_CLIENT_SECRET").unwrap_or_default(),
                auto_provision: env("OIDC_AUTO_PROVISION").map(|v| v == "true" || v == "1").unwrap_or(false),
            }),
            _ => None,
        };
        Ok(Config {
            database_url,
            listen_addr: env("LISTEN_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into()),
            public_url: env("PUBLIC_URL").unwrap_or_else(|| "http://localhost:8080".into()),
            blobs,
            oidc,
            local_auth: env("LOCAL_AUTH").map(|v| v != "false" && v != "0").unwrap_or(true),
            cors_origins: env("CORS_ORIGINS").map(|v| v.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
            maintenance_interval_secs: env("MAINTENANCE_INTERVAL_SECS").and_then(|v| v.parse().ok()).unwrap_or(3600),
        })
    }
}
