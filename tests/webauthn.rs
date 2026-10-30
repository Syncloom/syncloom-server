mod common;
use common::*;
use reqwest::Method;
use syncloom_core::client::{Auth, LoginOutcome};
use syncloom_core::vault::KdfParams;
use webauthn_authenticator_rs::{softtoken::SoftToken, WebauthnAuthenticator};
use webauthn_rs::prelude::{CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url};

/// Hardware security keys (WebAuthn/FIDO2) as the second factor, driven by a software authenticator.
#[tokio::test]
async fn security_key_enrollment_and_login() {
    let srv = start().await;
    let origin = Url::parse(&srv.state.cfg.public_url).unwrap();
    let auth = Auth::new(&srv.base);
    let http = reqwest::Client::new();
    let api = |p: &str| format!("{}/api/v1{}", srv.base, p);

    let reg = auth.register_with("alice", "pw", None, "browser", KdfParams::fast_for_tests()).await.unwrap();
    let LoginOutcome::EnrollRequired { token: enroll } = reg.outcome else { panic!() };

    // enroll a security key instead of an authenticator app
    let (soft, _) = SoftToken::new(false).unwrap();
    let mut key = WebauthnAuthenticator::new(soft);
    let challenge: CreationChallengeResponse = http.post(api("/auth/webauthn/register/start")).bearer_auth(&enroll).send().await.unwrap().json().await.unwrap();
    let cred: RegisterPublicKeyCredential = key.do_registration(origin.clone(), challenge).unwrap();
    let done = http.post(api("/auth/webauthn/register/finish?name=yubikey&device_name=laptop")).bearer_auth(&enroll).json(&cred).send().await.unwrap();
    assert!(done.status().is_success(), "{}", done.text().await.unwrap());
    let body: serde_json::Value = done.json().await.unwrap();
    assert_eq!(body["recovery_codes"].as_array().unwrap().len(), 10);
    let device = body["token"].as_str().unwrap().to_string();
    assert_eq!(raw(&srv, &device, Method::GET, "/me", None).await.0, 200);
    let me = raw(&srv, &device, Method::GET, "/me", None).await.1;
    assert_eq!(me["user"]["mfa_methods"], serde_json::json!(["webauthn", "recovery"]));

    // login: password, then the key
    let LoginOutcome::MfaRequired { token: mfa, methods } = auth.login("alice", "pw", "laptop").await.unwrap() else { panic!() };
    assert!(methods.contains(&"webauthn".to_string()));
    let challenge: RequestChallengeResponse = http.post(api("/auth/webauthn/login/start")).bearer_auth(&mfa).send().await.unwrap().json().await.unwrap();
    let assertion: PublicKeyCredential = key.do_authentication(origin.clone(), challenge).unwrap();
    let ok = http.post(api("/auth/webauthn/login/finish?device_name=laptop")).bearer_auth(&mfa).json(&assertion).send().await.unwrap();
    assert!(ok.status().is_success(), "{}", ok.text().await.unwrap());
    let session = ok.json::<serde_json::Value>().await.unwrap()["token"].as_str().unwrap().to_string();
    assert_eq!(raw(&srv, &session, Method::GET, "/me", None).await.0, 200);

    // a different (unregistered) key is rejected
    let LoginOutcome::MfaRequired { token: mfa2, .. } = auth.login("alice", "pw", "laptop").await.unwrap() else { panic!() };
    let challenge: RequestChallengeResponse = http.post(api("/auth/webauthn/login/start")).bearer_auth(&mfa2).send().await.unwrap().json().await.unwrap();
    let (other, _) = SoftToken::new(false).unwrap();
    let mut other = WebauthnAuthenticator::new(other);
    let _ = other.do_authentication(origin, challenge); // must not matter: the server decides
    let bad = http.post(api("/auth/webauthn/login/finish")).bearer_auth(&mfa2).json(&serde_json::json!({"id": "AAAA", "rawId": "AAAA", "response": {"authenticatorData": "AAAA", "clientDataJSON": "AAAA", "signature": "AAAA"}, "type": "public-key", "extensions": {}})).send().await.unwrap();
    assert!(!bad.status().is_success());
    // recovery codes also work for webauthn-only accounts
    let LoginOutcome::MfaRequired { token: mfa3, .. } = auth.login("alice", "pw", "laptop").await.unwrap() else { panic!() };
    auth.mfa_verify(&mfa3, "recovery", body["recovery_codes"][0].as_str().unwrap(), "laptop").await.unwrap();
}

/// Two hardware keys on one account (a spare in case one breaks): either one signs in.
#[tokio::test]
async fn two_security_keys_either_works() {
    let srv = start().await;
    let origin = Url::parse(&srv.state.cfg.public_url).unwrap();
    let auth = Auth::new(&srv.base);
    let http = reqwest::Client::new();
    let api = |p: &str| format!("{}/api/v1{}", srv.base, p);

    let LoginOutcome::EnrollRequired { token: enroll } = auth.register_with("alice", "pw", None, "d", KdfParams::fast_for_tests()).await.unwrap().outcome else { panic!() };
    let mut keys: Vec<WebauthnAuthenticator<SoftToken>> = (0..2).map(|_| WebauthnAuthenticator::new(SoftToken::new(false).unwrap().0)).collect();

    // first key during enrollment
    let ch: CreationChallengeResponse = http.post(api("/auth/webauthn/register/start")).bearer_auth(&enroll).send().await.unwrap().json().await.unwrap();
    let cred: RegisterPublicKeyCredential = keys[0].do_registration(origin.clone(), ch).unwrap();
    let r = http.post(api("/auth/webauthn/register/finish?name=primary&device_name=d")).bearer_auth(&enroll).json(&cred).send().await.unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    let session = body["token"].as_str().unwrap().to_string();

    // second key from an authenticated session;
    let ch: CreationChallengeResponse = http.post(api("/auth/webauthn/register/start")).bearer_auth(&session).send().await.unwrap().json().await.unwrap();
    let cred: RegisterPublicKeyCredential = keys[1].do_registration(origin.clone(), ch).unwrap();
    let r = http.post(api("/auth/webauthn/register/finish?name=spare")).bearer_auth(&session).json(&cred).send().await.unwrap();
    assert!(r.status().is_success());
    let body2: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body2["recovery_codes"].as_array().unwrap().len(), 0, "recovery codes are only issued with the first factor");

    let (_, methods) = raw(&srv, &session, Method::GET, "/me/mfa", None).await;
    assert_eq!(methods.as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect::<Vec<_>>(), vec!["primary", "spare"]);

    // each key can sign in on its own
    for i in [1usize, 0, 1] {
        let LoginOutcome::MfaRequired { token: mfa, .. } = auth.login("alice", "pw", "d").await.unwrap() else { panic!() };
        let ch: RequestChallengeResponse = http.post(api("/auth/webauthn/login/start")).bearer_auth(&mfa).send().await.unwrap().json().await.unwrap();
        let assertion: PublicKeyCredential = keys[i].do_authentication(origin.clone(), ch).unwrap();
        let ok = http.post(api("/auth/webauthn/login/finish?device_name=d")).bearer_auth(&mfa).json(&assertion).send().await.unwrap();
        assert!(ok.status().is_success(), "key {i}: {}", ok.text().await.unwrap());
    }

    // the primary breaks: remove it, the spare still works, and the spare cannot be removed
    let id0 = methods[0]["id"].as_str().unwrap();
    let id1 = methods[1]["id"].as_str().unwrap();
    assert_eq!(raw(&srv, &session, Method::DELETE, &format!("/me/mfa/{id0}"), None).await.0, 204);
    assert_eq!(raw(&srv, &session, Method::DELETE, &format!("/me/mfa/{id1}"), None).await.0, 409);
    let LoginOutcome::MfaRequired { token: mfa, .. } = auth.login("alice", "pw", "d").await.unwrap() else { panic!() };
    let ch: RequestChallengeResponse = http.post(api("/auth/webauthn/login/start")).bearer_auth(&mfa).send().await.unwrap().json().await.unwrap();
    let assertion: PublicKeyCredential = keys[1].do_authentication(origin, ch).unwrap();
    assert!(http.post(api("/auth/webauthn/login/finish?device_name=d")).bearer_auth(&mfa).json(&assertion).send().await.unwrap().status().is_success());
}
