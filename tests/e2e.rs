mod common;
use common::*;
use reqwest::Method;
use serde_json::json;
use std::time::Duration;
use syncloom_core::client::{Auth, Client, LoginOutcome, PublicClient};
use syncloom_core::error::Error;
use syncloom_core::vault::Vault;

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn scan_dir(dir: &std::path::Path, needle: &[u8]) -> bool {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            if scan_dir(&p, needle) {
                return true;
            }
        } else if contains_subslice(&std::fs::read(&p).unwrap(), needle) {
            return true;
        }
    }
    false
}

#[tokio::test]
async fn auth_flow_enforces_second_factor() {
    let srv = start().await;
    let alice = new_user(&srv, "alice", None).await;
    let auth = Auth::new(&srv.base);

    assert!(auth.login("alice", "wrong", "d").await.is_err());
    let LoginOutcome::MfaRequired { token, methods } = auth.login("alice", &alice.password, "laptop").await.unwrap() else {
        panic!("password alone must never give a device token")
    };
    assert!(methods.contains(&"totp".to_string()) && methods.contains(&"recovery".to_string()));

    // an MFA token is not a session
    let (st, _) = raw(&srv, &token, Method::GET, "/me", None).await;
    assert_eq!(st, 401);
    // a wrong code is rejected
    assert!(auth.mfa_verify(&token, "totp", "000000", "laptop").await.is_err());
    let code = totp_code(&alice.totp_url, 1);
    let device = auth.mfa_verify(&token, "totp", &code, "laptop").await.unwrap();
    assert_eq!(raw(&srv, &device, Method::GET, "/me", None).await.0, 200);
    // MFA token is single use
    assert!(auth.mfa_verify(&token, "totp", &code, "laptop").await.is_err());

    // replaying an already used TOTP code on a fresh login fails
    let LoginOutcome::MfaRequired { token: t2, .. } = auth.login("alice", &alice.password, "x").await.unwrap() else { panic!() };
    assert!(auth.mfa_verify(&t2, "totp", &code, "x").await.is_err());

    // recovery codes work exactly once
    let LoginOutcome::MfaRequired { token: t3, .. } = auth.login("alice", &alice.password, "x").await.unwrap() else { panic!() };
    auth.mfa_verify(&t3, "recovery", &alice.recovery_codes[0], "x").await.unwrap();
    let LoginOutcome::MfaRequired { token: t4, .. } = auth.login("alice", &alice.password, "x").await.unwrap() else { panic!() };
    assert!(auth.mfa_verify(&t4, "recovery", &alice.recovery_codes[0], "x").await.is_err());

    // an unenrolled account can only enroll, never use the API
    let LoginOutcome::EnrollRequired { token: enroll } = Auth::new(&srv.base)
        .register_with("bob", "pw", Some(&invite(&alice, &srv).await), "d", syncloom_core::vault::KdfParams::fast_for_tests())
        .await
        .unwrap()
        .outcome
    else {
        panic!()
    };
    assert_eq!(raw(&srv, &enroll, Method::GET, "/nodes", None).await.0, 401);
    let LoginOutcome::EnrollRequired { .. } = auth.login("bob", "pw", "d").await.unwrap() else { panic!("still must enroll") };

    // prelogin does not reveal whether a user exists
    let real = auth.prelogin("alice").await.unwrap();
    let fake1 = auth.prelogin("nobody-here").await.unwrap();
    let fake2 = auth.prelogin("nobody-here").await.unwrap();
    assert_eq!(fake1, fake2, "fake parameters must be stable");
    assert_eq!(real.m_kib, 8);

    // brute force protection
    for _ in 0..5 {
        let _ = auth.login("alice", "bad", "d").await;
    }
    let err = auth.login("alice", &alice.password, "d").await.unwrap_err();
    assert!(matches!(err, Error::Server { status: 429, .. }), "{err:?}");
}

#[tokio::test]
async fn registration_requires_invite_after_first_user() {
    let srv = start().await;
    let admin = new_user(&srv, "admin", None).await;
    let auth = Auth::new(&srv.base);
    let kdf = || syncloom_core::vault::KdfParams::fast_for_tests();

    assert!(auth.register_with("eve", "pw", None, "d", kdf()).await.is_err());
    assert!(auth.register_with("eve", "pw", Some("bogus"), "d", kdf()).await.is_err());
    let code = invite(&admin, &srv).await;
    auth.register_with("eve", "pw", Some(&code), "d", kdf()).await.unwrap();
    assert!(auth.register_with("mallory", "pw", Some(&code), "d", kdf()).await.is_err(), "invite is single use");
    assert!(auth.register_with("eve", "pw", Some(&invite(&admin, &srv).await), "d", kdf()).await.is_err(), "duplicate username");
    assert!(auth.register_with("Bad Name!", "pw", Some(&invite(&admin, &srv).await), "d", kdf()).await.is_err());

    // regular users cannot create invites or use admin endpoints
    let user = new_user(&srv, "carol", Some(&invite(&admin, &srv).await)).await;
    assert_eq!(raw(&srv, &user.token, Method::POST, "/admin/invites", None).await.0, 403);
    assert_eq!(raw(&srv, &user.token, Method::GET, "/admin/users", None).await.0, 403);
}

#[tokio::test]
async fn files_roundtrip_and_server_learns_nothing() {
    let srv = start().await;
    let a = new_user(&srv, "alice", None).await;
    let docs = a.client.create_folder(None, "Docs").await.unwrap();
    let data = pseudo_random(3_000_000, 7);
    let f = a.client.put_file(Some(&docs.id), "secret-plan-98765.bin", &data).await.unwrap();
    assert_eq!(f.size as usize, data.len());

    let list = a.client.list(Some(&docs.id)).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "secret-plan-98765.bin");
    assert_eq!(a.client.download_bytes(&f.id, None).await.unwrap(), data);

    // a second device with the same password sees the same tree
    let again = Client::connect(&srv.base, &a.token, &a.password).await.unwrap();
    assert_eq!(again.list(None).await.unwrap()[0].name, "Docs");
    assert_eq!(again.download_bytes(&f.id, None).await.unwrap(), data);
    assert!(Client::connect(&srv.base, &a.token, "wrong password").await.is_err());

    // zero knowledge: neither names nor contents appear anywhere on the server
    let marker = b"TOP-SECRET-MARKER-12345";
    let mut content = pseudo_random(5000, 3);
    content.extend_from_slice(marker);
    a.client.put_file(None, "marker-name-4242.txt", &content).await.unwrap();
    let rows: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT enc_name, enc_meta FROM nodes").fetch_all(&srv.state.db).await.unwrap();
    assert!(!rows.is_empty());
    for (n, m) in rows {
        assert!(!contains_subslice(&n, b"marker-name") && !contains_subslice(&n, b"Docs") && !contains_subslice(&m, b"mtime"));
    }
    assert!(!scan_dir(srv.blob_dir.path(), marker), "plaintext must not be in the blob store");
    let manifests: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT manifest FROM versions").fetch_all(&srv.state.db).await.unwrap();
    assert!(manifests.iter().all(|(m,)| !contains_subslice(m, b"content_hash")));

    // chunks are only readable by people who can reach a version that uses them
    let bob = new_user(&srv, "bob", Some(&invite(&a, &srv).await)).await;
    let hash: String = sqlx::query_scalar("SELECT hash FROM version_chunks LIMIT 1").fetch_one(&srv.state.db).await.unwrap();
    assert_eq!(raw(&srv, &bob.token, Method::GET, &format!("/chunks/{hash}"), None).await.0, 404);
    assert_eq!(raw(&srv, &a.token, Method::GET, &format!("/chunks/{hash}"), None).await.0, 200);
    // uploads are verified against their hash
    let r = reqwest::Client::new().put(format!("{}/api/v1/chunks/{}", srv.base, "ab".repeat(32))).bearer_auth(&a.token).body("not matching").send().await.unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn versions_conflicts_and_restore() {
    let srv = start().await;
    let a = new_user(&srv, "alice", None).await;
    let f = a.client.put_file(None, "a.txt", b"v1").await.unwrap();
    let v1 = f.head_version.clone().unwrap();
    let v2 = a.client.upload_bytes(&f.id, Some(&v1), b"v2").await.unwrap();
    // a client that still thinks v1 is the head must be told so
    let err = a.client.upload_bytes(&f.id, Some(&v1), b"v2-other-device").await.unwrap_err();
    assert!(matches!(err, Error::Conflict));
    assert_eq!(a.client.download_bytes(&f.id, None).await.unwrap(), b"v2");

    let versions = a.client.versions(&f.id).await.unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(a.client.download_bytes(&f.id, Some(&v1)).await.unwrap(), b"v1");
    let restored = a.client.restore_version(&f.id, &v1).await.unwrap();
    assert_ne!(restored.id, v1);
    assert_eq!(a.client.download_bytes(&f.id, None).await.unwrap(), b"v1");
    assert_eq!(a.client.versions(&f.id).await.unwrap().len(), 3);
    let _ = v2;

    // uploading a version that references chunks that were never uploaded is refused
    let (st, _) = raw(
        &srv,
        &a.token,
        Method::POST,
        &format!("/nodes/{}/versions", f.id),
        Some(json!({"id": uuid::Uuid::new_v4().to_string(), "base_version": restored.id, "size": 1, "manifest": "AAAA", "chunks": ["ab".repeat(32)]})),
    )
    .await;
    assert_eq!(st, 400);
}

#[tokio::test]
async fn trash_restore_purge_and_retention() {
    let srv = start().await;
    let a = new_user(&srv, "alice", None).await;
    let f = a.client.put_file(None, "gone.txt", b"hello trash").await.unwrap();
    a.client.trash(&f.id).await.unwrap();
    assert!(a.client.list(None).await.unwrap().is_empty());
    assert_eq!(a.client.trash_list().await.unwrap()[0].name, "gone.txt");
    a.client.restore(&f.id).await.unwrap();
    assert_eq!(a.client.list(None).await.unwrap().len(), 1);
    assert!(matches!(a.client.purge(&f.id).await.unwrap_err(), Error::Server { .. } | Error::Conflict), "only trashed items can be purged");

    // retention settings are admin-configurable and drive the background job
    let (st, _) = raw(&srv, &a.token, Method::PUT, "/admin/settings", Some(json!({"trash_days": 0, "version_days": 0, "keep_latest_versions": 1, "default_quota_bytes": null}))).await;
    assert_eq!(st, 200);
    let g = a.client.put_file(None, "versions.txt", b"one").await.unwrap();
    let v = a.client.upload_bytes(&g.id, g.head_version.as_deref(), b"two").await.unwrap();
    a.client.upload_bytes(&g.id, Some(&v.id), b"three").await.unwrap();
    assert_eq!(a.client.versions(&g.id).await.unwrap().len(), 3);
    a.client.trash(&f.id).await.unwrap();
    let blobs_before = std::fs::read_dir(srv.blob_dir.path().join("chunks")).unwrap().count();
    assert!(blobs_before > 0);

    let report = syncloom_server::jobs::run_maintenance(&srv.state, 0).await.unwrap();
    assert_eq!(report.purged_nodes, 1);
    assert_eq!(report.pruned_versions, 2, "keeps only the head");
    assert!(report.deleted_chunks >= 2);
    assert!(a.client.trash_list().await.unwrap().is_empty());
    assert_eq!(a.client.versions(&g.id).await.unwrap().len(), 1);
    assert_eq!(a.client.download_bytes(&g.id, None).await.unwrap(), b"three");
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM chunks").fetch_one(&srv.state.db).await.unwrap();
    assert_eq!(remaining, 1, "only the head's chunk is left");
}

#[tokio::test]
async fn key_value_store() {
    let srv = start().await;
    let a = new_user(&srv, "alice", None).await;
    let ns = a.client.kv_create_namespace(None, "settings").await.unwrap();
    let e = a.client.kv_put(&ns.id, "theme/color", b"blue", None).await.unwrap();
    assert_eq!(e.version, 1);
    a.client.kv_put(&ns.id, "theme/font", b"mono", None).await.unwrap();
    a.client.kv_put(&ns.id, "other", b"x", None).await.unwrap();
    assert_eq!(a.client.kv_list(&ns.id, "theme/").await.unwrap().len(), 2);
    assert_eq!(a.client.kv_get(&ns.id, "theme/color").await.unwrap().unwrap().value, b"blue");

    // compare-and-set
    assert!(matches!(a.client.kv_put(&ns.id, "theme/color", b"red", Some(0)).await.unwrap_err(), Error::Conflict));
    assert!(matches!(a.client.kv_put(&ns.id, "theme/color", b"red", Some(7)).await.unwrap_err(), Error::Conflict));
    assert_eq!(a.client.kv_put(&ns.id, "theme/color", b"red", Some(1)).await.unwrap().version, 2);
    // last writer wins without a condition
    assert_eq!(a.client.kv_put(&ns.id, "theme/color", b"green", None).await.unwrap().version, 3);
    assert!(a.client.kv_put(&ns.id, "fresh", b"1", Some(0)).await.is_ok());

    a.client.kv_delete(&ns.id, "theme/color", None).await.unwrap();
    assert!(a.client.kv_get(&ns.id, "theme/color").await.unwrap().is_none());
    assert_eq!(a.client.kv_list(&ns.id, "theme/").await.unwrap().len(), 1);
    assert!(a.client.kv_put(&ns.id, "theme/color", b"again", Some(0)).await.is_ok(), "deleted keys can be recreated");
    assert!(a.client.kv_put(&ns.id, "big", &vec![0u8; 300 * 1024], None).await.is_err());

    // values and keys-as-plaintext: values are ciphertext on the server
    let stored: Vec<u8> = sqlx::query_scalar("SELECT value FROM kv_entries WHERE key = 'other'").fetch_one(&srv.state.db).await.unwrap();
    assert_ne!(stored, b"x");
    assert!(stored.len() > 24 + 16);

    // shared namespaces
    let bob = new_user(&srv, "bob", Some(&invite(&a, &srv).await)).await;
    a.client.share(&ns.id, "bob", "rw").await.unwrap();
    assert_eq!(bob.client.kv_get(&ns.id, "other").await.unwrap().unwrap().value, b"x");
    bob.client.kv_put(&ns.id, "from-bob", b"hi", None).await.unwrap();
    assert_eq!(a.client.kv_get(&ns.id, "from-bob").await.unwrap().unwrap().value, b"hi");
    // the namespace shows up in the change feed with its key
    let ch = a.client.changes(0, 1000).await.unwrap();
    assert!(ch.changes.iter().any(|c| c.kind == "kv" && c.kv_key.as_deref() == Some("from-bob")));
}

#[tokio::test]
async fn sharing_between_users() {
    let srv = start().await;
    let alice = new_user(&srv, "alice", None).await;
    let bob = new_user(&srv, "bob", Some(&invite(&alice, &srv).await)).await;
    let carol = new_user(&srv, "carol", Some(&invite(&alice, &srv).await)).await;

    let project = alice.client.create_folder(None, "Project").await.unwrap();
    let plan = alice.client.put_file(Some(&project.id), "plan.txt", b"the plan").await.unwrap();
    assert!(alice.client.share(&project.id, "alice", "ro").await.is_err());
    assert!(alice.client.share(&project.id, "nobody", "ro").await.is_err());
    alice.client.share(&project.id, "bob", "ro").await.unwrap();

    // bob can read through the share but not write
    let shared = bob.client.shared_with_me().await.unwrap();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].name, "Project");
    assert_eq!(shared[0].access, "ro");
    let kids = bob.client.list(Some(&project.id)).await.unwrap();
    assert_eq!(kids[0].name, "plan.txt");
    assert_eq!(bob.client.download_bytes(&plan.id, None).await.unwrap(), b"the plan");
    assert!(matches!(bob.client.create_file_node(Some(&project.id), "x.txt", &Default::default()).await.unwrap_err(), Error::Server { status: 403, .. }));
    assert!(bob.client.trash(&plan.id).await.is_err());
    assert!(carol.client.list(Some(&project.id)).await.is_err(), "unshared users get nothing");
    assert!(carol.client.download_bytes(&plan.id, None).await.is_err());

    // upgrade to read-write
    alice.client.share(&project.id, "bob", "rw").await.unwrap();
    let theirs = bob.client.put_file(Some(&project.id), "from-bob.txt", b"hello alice").await.unwrap();
    assert_eq!(alice.client.download_bytes(&theirs.id, None).await.unwrap(), b"hello alice");
    let v = bob.client.upload_bytes(&plan.id, plan.head_version.as_deref(), b"the plan, edited").await.unwrap();
    assert!(!v.id.is_empty());
    assert_eq!(alice.client.download_bytes(&plan.id, None).await.unwrap(), b"the plan, edited");
    // content created by a sharee counts against the owner
    let owner: String = sqlx::query_scalar("SELECT owner_id::text FROM nodes WHERE id = $1::uuid").bind(&theirs.id).fetch_one(&srv.state.db).await.unwrap();
    assert_eq!(owner, alice.client.user_id());

    // change feeds are per user
    let bob_changes = bob.client.changes(0, 1000).await.unwrap();
    assert!(bob_changes.changes.iter().any(|c| c.kind == "share" && c.node_id == project.id));
    assert!(bob_changes.changes.iter().any(|c| c.kind == "version" && c.node_id == plan.id));
    assert!(carol.client.changes(0, 1000).await.unwrap().changes.is_empty());

    // revoke
    let shares = alice.client.shares(&project.id).await.unwrap();
    assert_eq!(shares.len(), 1);
    alice.client.unshare(&shares[0].id).await.unwrap();
    assert!(bob.client.shared_with_me().await.unwrap().is_empty());
    let fresh_bob = Client::connect(&srv.base, &bob.token, &bob.password).await.unwrap();
    assert!(fresh_bob.list(Some(&project.id)).await.is_err());
    assert!(fresh_bob.download_bytes(&plan.id, None).await.is_err());
}

#[tokio::test]
async fn public_links() {
    let srv = start().await;
    let a = new_user(&srv, "alice", None).await;
    let folder = a.client.create_folder(None, "Public").await.unwrap();
    let sub = a.client.create_folder(Some(&folder.id), "nested").await.unwrap();
    let file = a.client.put_file(Some(&sub.id), "hello.txt", b"hello world").await.unwrap();
    let top = a.client.put_file(Some(&folder.id), "top.txt", b"top").await.unwrap();

    // folder link: browse and download without an account
    let link = a.client.create_link(&folder.id, None, None, None).await.unwrap();
    let pc = PublicClient::open(&srv.base, &link.token, &link.link_key, None).await.unwrap();
    assert_eq!(pc.root.name, "Public");
    let kids = pc.list(None, None).await.unwrap();
    assert_eq!(kids.len(), 2);
    let (nested, nkey) = kids.iter().find(|(n, _)| n.name == "nested").unwrap();
    let inner = pc.list(Some(nested), Some(nkey)).await.unwrap();
    assert_eq!(pc.download(&inner[0].0, &inner[0].1).await.unwrap(), b"hello world");
    // wrong key cannot open it; the server never sees the right one
    assert!(PublicClient::open(&srv.base, &link.token, &syncloom_core::b64::encode(&[7u8; 32]), None).await.is_err());
    // nodes outside the link are not reachable through it
    let (st, _) = raw(&srv, "", Method::GET, &format!("/public/{}/versions/{}", link.token, uuid::Uuid::new_v4()), None).await;
    assert_eq!(st, 404);

    // password + download limit on a single file
    let l2 = a.client.create_link(&top.id, Some("hunter2"), None, Some(1)).await.unwrap();
    assert!(PublicClient::open(&srv.base, &l2.token, &l2.link_key, None).await.is_err());
    assert!(PublicClient::open(&srv.base, &l2.token, &l2.link_key, Some("wrong")).await.is_err());
    let pc2 = PublicClient::open(&srv.base, &l2.token, &l2.link_key, Some("hunter2")).await.unwrap();
    assert_eq!(pc2.download(&pc2.root, &pc2.root_key()).await.unwrap(), b"top");
    assert!(pc2.download(&pc2.root, &pc2.root_key()).await.is_err(), "limit of one download");

    // expired and revoked
    let past = chrono_ms() - 1000;
    let l3 = a.client.create_link(&top.id, None, Some(past), None).await.unwrap();
    assert!(PublicClient::open(&srv.base, &l3.token, &l3.link_key, None).await.is_err());
    assert_eq!(a.client.links(&folder.id).await.unwrap().len(), 1);
    a.client.delete_link(&link.id).await.unwrap();
    assert!(PublicClient::open(&srv.base, &link.token, &link.link_key, None).await.is_err());
    let _ = file;

    // others cannot manage someone else's links
    let bob = new_user(&srv, "bob", Some(&invite(&a, &srv).await)).await;
    assert!(bob.client.create_link(&folder.id, None, None, None).await.is_err());
}

fn chrono_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

#[tokio::test]
async fn change_feed_rest_and_grpc() {
    let srv = start().await;
    let a = new_user(&srv, "alice", None).await;
    let f = a.client.put_file(None, "one.txt", b"1").await.unwrap();
    let head = a.client.changes_head().await.unwrap();
    assert!(head > 0);
    let all = a.client.changes(0, 100).await.unwrap();
    assert_eq!(all.next_cursor, head);
    assert!(all.changes.iter().any(|c| c.kind == "node" && c.node_id == f.id));
    assert!(all.changes.iter().any(|c| c.kind == "version"));
    assert!(a.client.changes(head, 100).await.unwrap().changes.is_empty());

    // gRPC: history first, then live pushes
    let mut stream = a.client.subscribe(0).await.unwrap();
    let mut seen = 0;
    while seen < all.changes.len() {
        let c = tokio::time::timeout(Duration::from_secs(5), stream.next_change()).await.unwrap().unwrap().unwrap();
        assert_eq!(c.cursor, all.changes[seen].cursor);
        seen += 1;
    }
    let token = a.token.clone();
    let base = srv.base.clone();
    let password = a.password.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let c = Client::connect(&base, &token, &password).await.unwrap();
        c.put_file(None, "live.txt", b"live").await.unwrap();
    });
    let live = tokio::time::timeout(Duration::from_secs(5), stream.next_change()).await.expect("live change must arrive").unwrap().unwrap();
    assert!(live.cursor > head);
    assert_eq!(live.kind, "node");

    // the stream needs a valid token
    let bad = Client::with_vault(&srv.base, &a.token, Vault::create("x", syncloom_core::vault::KdfParams::fast_for_tests()).unwrap().vault).await.unwrap();
    let _ = bad; // same token, still valid: only revoked/invalid tokens must fail
    let rawc = reqwest::Client::new().post(format!("{}/syncloom.sync.v1.Sync/Subscribe", srv.base)).header("content-type", "application/grpc").body(vec![0u8, 0, 0, 0, 0]).send().await.unwrap();
    assert_ne!(rawc.headers().get("grpc-status").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default(), "0");
}

#[tokio::test]
async fn admin_controls() {
    let srv = start().await;
    let admin = new_user(&srv, "admin", None).await;
    let bob = new_user(&srv, "bob", Some(&invite(&admin, &srv).await)).await;
    let (_, users) = raw(&srv, &admin.token, Method::GET, "/admin/users", None).await;
    assert_eq!(users.as_array().unwrap().len(), 2);
    let bob_id = users.as_array().unwrap().iter().find(|u| u["username"] == "bob").unwrap()["id"].as_str().unwrap().to_string();

    // quotas count every stored version
    let (st, _) = raw(&srv, &admin.token, Method::PATCH, &format!("/admin/users/{bob_id}"), Some(json!({"quota_bytes": 1000}))).await;
    assert_eq!(st, 204);
    bob.client.put_file(None, "small.txt", &vec![b'a'; 600]).await.unwrap();
    let err = bob.client.put_file(None, "big.txt", &vec![b'b'; 600]).await.unwrap_err();
    assert!(matches!(err, Error::Server { status: 413, .. }), "{err:?}");
    assert_eq!(bob.client.me().await.unwrap().user.quota_bytes, Some(1000));
    assert_eq!(bob.client.me().await.unwrap().user.used_bytes, 600);

    // 2FA reset forces re-enrollment and signs the user out
    let (st, _) = raw(&srv, &admin.token, Method::POST, &format!("/admin/users/{bob_id}/reset-2fa"), None).await;
    assert_eq!(st, 204);
    assert_eq!(raw(&srv, &bob.token, Method::GET, "/me", None).await.0, 401);
    let LoginOutcome::EnrollRequired { .. } = Auth::new(&srv.base).login("bob", &bob.password, "d").await.unwrap() else { panic!() };

    // disabling a user revokes access
    let carol = new_user(&srv, "carol", Some(&invite(&admin, &srv).await)).await;
    let (_, users) = raw(&srv, &admin.token, Method::GET, "/admin/users", None).await;
    let carol_id = users.as_array().unwrap().iter().find(|u| u["username"] == "carol").unwrap()["id"].as_str().unwrap().to_string();
    raw(&srv, &admin.token, Method::PATCH, &format!("/admin/users/{carol_id}"), Some(json!({"disabled": true}))).await;
    assert_eq!(raw(&srv, &carol.token, Method::GET, "/me", None).await.0, 401);
    assert!(Auth::new(&srv.base).login("carol", &carol.password, "d").await.is_err());

    // the last admin cannot be removed
    let admin_id = users.as_array().unwrap().iter().find(|u| u["username"] == "admin").unwrap()["id"].as_str().unwrap().to_string();
    assert_eq!(raw(&srv, &admin.token, Method::PATCH, &format!("/admin/users/{admin_id}"), Some(json!({"role": "user"}))).await.0, 409);
    assert_eq!(raw(&srv, &admin.token, Method::DELETE, &format!("/admin/users/{admin_id}"), None).await.0, 409);

    let (st, s) = raw(&srv, &admin.token, Method::GET, "/admin/settings", None).await;
    assert_eq!((st, s["trash_days"].as_i64()), (200, Some(30)));
    assert_eq!(raw(&srv, &admin.token, Method::PUT, "/admin/settings", Some(json!({"trash_days": -1, "version_days": 1, "keep_latest_versions": 1, "default_quota_bytes": null}))).await.0, 400);
}

#[tokio::test]
async fn move_rename_and_key_rewrapping() {
    let srv = start().await;
    let a = new_user(&srv, "alice", None).await;
    let fa = a.client.create_folder(None, "A").await.unwrap();
    let fb = a.client.create_folder(None, "B").await.unwrap();
    let inner = a.client.create_folder(Some(&fa.id), "inner").await.unwrap();
    let file = a.client.put_file(Some(&fa.id), "doc.txt", b"moving").await.unwrap();

    a.client.move_to(&file.id, Some(&fb.id)).await.unwrap();
    assert!(a.client.list(Some(&fa.id)).await.unwrap().iter().all(|n| n.name != "doc.txt"));
    // a fresh client (empty key cache) must be able to unwrap the key through the new parent
    let fresh = Client::connect(&srv.base, &a.token, &a.password).await.unwrap();
    assert_eq!(fresh.list(Some(&fb.id)).await.unwrap()[0].name, "doc.txt");
    assert_eq!(fresh.download_bytes(&file.id, None).await.unwrap(), b"moving");

    a.client.rename(&file.id, "renamed.txt").await.unwrap();
    assert_eq!(Client::connect(&srv.base, &a.token, &a.password).await.unwrap().get(&file.id).await.unwrap().name, "renamed.txt");
    a.client.move_to(&file.id, None).await.unwrap();
    assert_eq!(Client::connect(&srv.base, &a.token, &a.password).await.unwrap().download_bytes(&file.id, None).await.unwrap(), b"moving");

    // no cycles, no invalid names
    assert!(a.client.move_to(&fa.id, Some(&inner.id)).await.is_err());
    assert!(a.client.move_to(&fa.id, Some(&fa.id)).await.is_err());
    assert!(a.client.create_folder(None, "bad/name").await.is_err());
    assert!(a.client.rename(&file.id, "CON").await.is_err());
}

#[tokio::test]
async fn password_change_recovery_key_and_devices() {
    let srv = start().await;
    let a = new_user(&srv, "alice", None).await;
    let f = a.client.put_file(None, "keep.txt", b"important").await.unwrap();

    // a second device
    let auth = Auth::new(&srv.base);
    let LoginOutcome::MfaRequired { token, .. } = auth.login("alice", &a.password, "phone").await.unwrap() else { panic!() };
    let phone = auth.mfa_verify(&token, "totp", &totp_code(&a.totp_url, 1), "phone").await.unwrap();
    let devices = a.client.devices().await.unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().any(|d| d.current && d.name == "test-device"));

    a.client.change_password(&a.password, "a brand new password").await.unwrap();
    assert_eq!(raw(&srv, &phone, Method::GET, "/me", None).await.0, 401, "other sessions are revoked");
    assert_eq!(raw(&srv, &a.token, Method::GET, "/me", None).await.0, 200, "the current one stays");
    assert!(Client::connect(&srv.base, &a.token, &a.password).await.is_err());
    let c = Client::connect(&srv.base, &a.token, "a brand new password").await.unwrap();
    assert_eq!(c.download_bytes(&f.id, None).await.unwrap(), b"important", "data survives a password change");
    assert!(a.client.change_password("wrong", "x").await.is_err());
    assert!(auth.login("alice", &a.password, "d").await.is_err());
    assert!(matches!(auth.login("alice", "a brand new password", "d").await.unwrap(), LoginOutcome::MfaRequired { .. }));

    // recovery key unlocks the vault when the password is forgotten
    let me = c.me().await.unwrap();
    let vault = Vault::unlock_with_recovery(&a.recovery_key, &me.vault.unwrap()).unwrap();
    let recovered = Client::with_vault(&srv.base, &a.token, vault).await.unwrap();
    assert_eq!(recovered.download_bytes(&f.id, None).await.unwrap(), b"important");

    // revoke a device
    let others: Vec<_> = c.devices().await.unwrap().into_iter().filter(|d| !d.current).collect();
    for d in others {
        let (st, _) = raw(&srv, &a.token, Method::DELETE, &format!("/me/devices/{}", d.id), None).await;
        assert_eq!(st, 204);
    }
    assert_eq!(c.devices().await.unwrap().len(), 1);
    c.logout().await.unwrap();
    assert_eq!(raw(&srv, &a.token, Method::GET, "/me", None).await.0, 401);
}

#[tokio::test]
async fn multiple_second_factors_any_one_suffices() {
    let srv = start().await;
    let a = new_user(&srv, "alice", None).await;
    let auth = Auth::new(&srv.base);

    // add two more authenticator apps as fallbacks
    let phone = a.client.add_totp("Phone").await.unwrap();
    a.client.confirm_totp(&phone.id, &totp_code(&phone.otpauth_url, -1)).await.unwrap();
    let tablet = a.client.add_totp("Tablet").await.unwrap();
    a.client.confirm_totp(&tablet.id, &totp_code(&tablet.otpauth_url, -1)).await.unwrap();
    let methods = a.client.mfa_methods().await.unwrap();
    assert_eq!(methods.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(), vec!["test app", "Phone", "Tablet"]);

    // each of them works on its own (distinct secrets, distinct replay counters)
    for (url, step) in [(&a.totp_url, 1), (&phone.otpauth_url, 0), (&tablet.otpauth_url, 0)] {
        let LoginOutcome::MfaRequired { token, methods } = auth.login("alice", &a.password, "d").await.unwrap() else { panic!() };
        assert!(methods.contains(&"totp".to_string()));
        auth.mfa_verify(&token, "totp", &totp_code(url, step), "d").await.unwrap();
    }
    // a pending (unconfirmed) authenticator must not count as a factor
    let pending = a.client.add_totp("Not confirmed").await.unwrap();
    let LoginOutcome::MfaRequired { token, .. } = auth.login("alice", &a.password, "d").await.unwrap() else { panic!() };
    assert!(auth.mfa_verify(&token, "totp", &totp_code(&pending.otpauth_url, 0), "d").await.is_err());
    assert_eq!(a.client.mfa_methods().await.unwrap().len(), 3);

    // losing one is fine
    a.client.rename_mfa(&methods[1].id, "Old phone").await.unwrap();
    a.client.remove_mfa(&methods[1].id).await.unwrap();
    let LoginOutcome::MfaRequired { token, .. } = auth.login("alice", &a.password, "d").await.unwrap() else { panic!() };
    assert!(auth.mfa_verify(&token, "totp", &totp_code(&phone.otpauth_url, 1), "d").await.is_err(), "removed factor stops working");
    let LoginOutcome::MfaRequired { token, .. } = auth.login("alice", &a.password, "d").await.unwrap() else { panic!() };
    auth.mfa_verify(&token, "totp", &totp_code(&tablet.otpauth_url, 1), "d").await.unwrap();

    // the last one cannot be removed
    let left = a.client.mfa_methods().await.unwrap();
    assert_eq!(left.len(), 2);
    a.client.remove_mfa(&left[0].id).await.unwrap();
    assert!(matches!(a.client.remove_mfa(&left[1].id).await.unwrap_err(), Error::Conflict));

    // recovery codes can be regenerated, which invalidates the old set
    let fresh = a.client.new_recovery_codes().await.unwrap();
    assert_eq!(fresh.len(), 10);
    let LoginOutcome::MfaRequired { token, .. } = auth.login("alice", &a.password, "d").await.unwrap() else { panic!() };
    assert!(auth.mfa_verify(&token, "recovery", &a.recovery_codes[1], "d").await.is_err());
    auth.mfa_verify(&token, "recovery", &fresh[0], "d").await.unwrap();
}
