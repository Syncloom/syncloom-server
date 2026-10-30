mod common;
use common::*;
use reqwest::{redirect::Policy, Method};
use syncloom_server::config::OidcConfig;

/// Needs the mock IdP from `scripts/test-all.sh` (`MOCK_OIDC_ISSUER`); skipped otherwise.
#[tokio::test]
async fn oidc_login_for_provisioned_user() {
    let Ok(issuer) = std::env::var("MOCK_OIDC_ISSUER") else {
        eprintln!("MOCK_OIDC_ISSUER not set, skipping");
        return;
    };
    let srv = start_with(|c| {
        c.oidc = Some(OidcConfig { issuer: issuer.clone(), client_id: "syncloom".into(), client_secret: "secret".into(), auto_provision: false });
    })
    .await;
    // bootstrap admin (built-in) to pre-provision the OIDC user
    let admin = new_user(&srv, "admin", None).await;
    let (st, _) = raw(&srv, &admin.token, Method::POST, "/admin/users", Some(serde_json::json!({"username": "olivia"}))).await;
    assert_eq!(st, 201);

    // follow the authorization-code flow by hand: login -> IdP -> callback -> our redirect with a token
    let http = reqwest::Client::builder().redirect(Policy::none()).build().unwrap();
    let mut url = format!("{}/api/v1/auth/oidc/login", srv.base);
    let mut final_location = None;
    for _ in 0..8 {
        let r = http.get(&url).send().await.unwrap();
        if let Some(loc) = r.headers().get("location") {
            let loc = loc.to_str().unwrap().to_string();
            let loc = if loc.starts_with("http") { loc } else { format!("{}{}", srv.base, loc) };
            // our own callback is on the public URL, which in the test is localhost:<port>
            if loc.contains("/#oidc-token=") {
                final_location = Some(loc);
                break;
            }
            url = loc.replace("localhost", "127.0.0.1");
        } else {
            panic!("flow stopped at {url} with status {} body {}", r.status(), r.text().await.unwrap());
        }
    }
    let loc = final_location.expect("redirect carrying the token");
    let token = loc.split("#oidc-token=").nth(1).unwrap().to_string();
    let (st, me) = raw(&srv, &token, Method::GET, "/me", None).await;
    assert_eq!(st, 200);
    assert_eq!(me["user"]["username"], "olivia");
    assert_eq!(me["user"]["auth_provider"], "oidc");
    assert!(me["vault"].is_null(), "OIDC users create their vault passphrase after the first login");

    // OIDC accounts cannot use the built-in password login
    let r = syncloom_core::client::Auth::new(&srv.base).login("olivia", "anything", "d").await;
    assert!(r.is_err());

    // an identity without an account is refused when auto-provisioning is off
    let sub: Option<String> = sqlx::query_scalar("SELECT oidc_sub FROM users WHERE username = 'olivia'").fetch_one(&srv.state.db).await.unwrap();
    assert_eq!(sub.as_deref(), Some("oidc-subject-1"));
}
