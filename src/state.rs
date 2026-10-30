use crate::{blobs::Blobs, config::Config};
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc, sync::Mutex, time::Instant};
use tokio::sync::broadcast;
use uuid::Uuid;
use webauthn_rs::prelude::{SecurityKeyAuthentication, SecurityKeyRegistration, Webauthn};

pub struct Inner {
    pub db: PgPool,
    pub cfg: Config,
    pub blobs: Blobs,
    /// User ids that have new changes. Subscribers filter on their own id.
    pub notify: broadcast::Sender<Uuid>,
    pub webauthn: Option<Webauthn>,
    pub wa_reg: Mutex<HashMap<Uuid, (SecurityKeyRegistration, Instant)>>,
    pub wa_auth: Mutex<HashMap<Uuid, (SecurityKeyAuthentication, Instant)>>,
    pub oidc_pending: Mutex<HashMap<String, (String, String, Instant)>>,
    pub login_attempts: Mutex<HashMap<String, (u32, Instant)>>,
    /// Stable per-installation secret (used for fake prelogin params).
    pub server_secret: Vec<u8>,
}

pub type AppState = Arc<Inner>;

impl Inner {
    pub fn notify_users(&self, users: &[Uuid]) {
        for u in users {
            let _ = self.notify.send(*u);
        }
    }

    /// Returns Err(retry) if too many recent failures. Window: 5 failures / 15 minutes.
    pub fn check_login_allowed(&self, key: &str) -> bool {
        let mut m = self.login_attempts.lock().unwrap();
        match m.get(key) {
            Some((n, since)) if since.elapsed().as_secs() < 900 => *n < 5,
            Some(_) => {
                m.remove(key);
                true
            }
            None => true,
        }
    }
    pub fn record_login_failure(&self, key: &str) {
        let mut m = self.login_attempts.lock().unwrap();
        let e = m.entry(key.to_string()).or_insert((0, Instant::now()));
        if e.1.elapsed().as_secs() >= 900 {
            *e = (0, Instant::now());
        }
        e.0 += 1;
    }
    pub fn clear_login_failures(&self, key: &str) {
        self.login_attempts.lock().unwrap().remove(key);
    }
}
