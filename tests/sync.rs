mod common;
use common::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{atomic::{AtomicU64, Ordering}, Arc};
use std::time::{Duration, SystemTime};
use syncloom_core::client::Client;
use syncloom_core::state::StateDb;
use syncloom_core::sync::{SyncConfig, SyncEngine, SyncReport};

static CLOCK: AtomicU64 = AtomicU64::new(1);

struct Device {
    dir: tempfile::TempDir,
    engine: SyncEngine,
}

impl Device {
    async fn new(srv: &TestServer, user: &User, name: &str) -> Device {
        let dir = tempfile::tempdir().unwrap();
        let client = Arc::new(Client::connect(&srv.base, &user.token, &user.password).await.unwrap());
        let engine = SyncEngine::new(client, SyncConfig { root: dir.path().to_path_buf(), device: name.into() }, StateDb::in_memory().unwrap()).unwrap();
        Device { dir, engine }
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    /// Writes a file and gives it a unique mtime so edits are never mistaken for "unchanged".
    fn write(&self, rel: &str, content: impl AsRef<[u8]>) {
        let p = self.p(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, content).unwrap();
        let t = SystemTime::now() + Duration::from_secs(CLOCK.fetch_add(10, Ordering::SeqCst));
        fs::File::options().write(true).open(&p).unwrap().set_modified(t).unwrap();
    }
    fn read(&self, rel: &str) -> Vec<u8> {
        fs::read(self.p(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
    }
    fn text(&self, rel: &str) -> String {
        String::from_utf8(self.read(rel)).unwrap()
    }
    fn exists(&self, rel: &str) -> bool {
        self.p(rel).exists()
    }
    async fn sync(&mut self) -> SyncReport {
        let r = self.engine.sync_once().await.unwrap();
        assert!(r.errors.is_empty(), "sync errors: {:?}", r.errors);
        r
    }
    /// Sorted list of all files and folders (relative paths), ignoring engine temp files.
    fn tree(&self) -> Vec<String> {
        fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
            for e in fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let rel = e.path().strip_prefix(base).unwrap().to_string_lossy().to_string();
                if rel.contains(".syncloom-tmp-") {
                    continue;
                }
                if e.path().is_dir() {
                    out.push(format!("{rel}/"));
                    walk(base, &e.path(), out);
                } else {
                    out.push(rel);
                }
            }
        }
        let mut out = vec![];
        walk(self.dir.path(), self.dir.path(), &mut out);
        out.sort();
        out
    }
}

async fn setup() -> (TestServer, User, Device, Device) {
    let srv = start().await;
    let user = new_user(&srv, "alice", None).await;
    let a = Device::new(&srv, &user, "laptop").await;
    let b = Device::new(&srv, &user, "phone").await;
    (srv, user, a, b)
}

/// Two devices that are in sync end up with identical trees and identical file contents.
fn assert_same(a: &Device, b: &Device) {
    assert_eq!(a.tree(), b.tree(), "trees differ");
    for f in a.tree().into_iter().filter(|f| !f.ends_with('/')) {
        assert_eq!(a.read(&f), b.read(&f), "content of {f} differs");
    }
}

#[tokio::test]
async fn files_and_folders_propagate() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("hello.txt", "hello");
    a.write("docs/nested/deep.txt", "deep");
    a.write("empty.bin", "");
    a.write("ünïcödé 日本語.txt", "unicode");
    let big: Vec<u8> = pseudo_random(3_000_000, 5);
    a.write("big.bin", &big);
    fs::create_dir_all(a.p("emptydir")).unwrap();
    let r = a.sync().await;
    assert_eq!(r.uploaded.len(), 8, "{:?}", r.uploaded);
    assert!(r.conflicts.is_empty());

    let r = b.sync().await;
    assert_eq!(r.downloaded.len(), 5, "{:?}", r.downloaded);
    assert_same(&a, &b);
    assert_eq!(b.read("big.bin"), big);
    assert!(b.exists("emptydir"));

    // nothing left to do on either side, and nothing is re-transferred
    assert!(a.sync().await.is_empty());
    assert!(b.sync().await.is_empty());
}

#[tokio::test]
async fn edits_deletes_and_moves_propagate() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("notes/todo.txt", "one");
    a.write("notes/keep.txt", "keep");
    a.write("old/data.txt", "data");
    a.sync().await;
    b.sync().await;

    // edit
    a.write("notes/todo.txt", "one\ntwo\n");
    a.sync().await;
    let r = b.sync().await;
    assert_eq!(r.downloaded, vec!["notes/todo.txt"]);
    assert_eq!(b.text("notes/todo.txt"), "one\ntwo\n");

    // delete
    fs::remove_file(a.p("notes/keep.txt")).unwrap();
    let r = a.sync().await;
    assert_eq!(r.trashed_remote, vec!["notes/keep.txt"]);
    let r = b.sync().await;
    assert_eq!(r.deleted_local, vec!["notes/keep.txt"]);
    assert!(!b.exists("notes/keep.txt"));

    // rename a folder: only metadata changes, no content is transferred
    fs::rename(a.p("old"), a.p("archive")).unwrap();
    let r = a.sync().await;
    assert_eq!(r.moved, vec!["archive"], "a local rename is applied as a rename: {r:?}");
    assert!(r.uploaded.is_empty() && r.trashed_remote.is_empty());
    let r = b.sync().await;
    assert!(r.downloaded.is_empty(), "a rename must not re-download: {:?}", r.downloaded);
    assert!(!b.exists("old") && b.text("archive/data.txt") == "data");

    // delete a whole folder tree
    fs::remove_dir_all(a.p("notes")).unwrap();
    a.sync().await;
    b.sync().await;
    assert!(!b.exists("notes"));
    assert_same(&a, &b);
}

#[tokio::test]
async fn concurrent_text_edits_merge_automatically() {
    let (_srv, _u, mut a, mut b) = setup().await;
    let base = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\n";
    a.write("doc.txt", base);
    a.sync().await;
    b.sync().await;

    a.write("doc.txt", base.replace("line1", "LINE1 from laptop"));
    b.write("doc.txt", base.replace("line8", "LINE8 from phone"));
    a.sync().await;
    let r = b.sync().await;
    assert_eq!(r.merged, vec!["doc.txt"], "{r:?}");
    assert!(r.conflicts.is_empty());
    let merged = b.text("doc.txt");
    assert!(merged.contains("LINE1 from laptop") && merged.contains("LINE8 from phone"));
    a.sync().await;
    assert_eq!(a.text("doc.txt"), merged);
    assert_same(&a, &b);
    assert!(!b.tree().iter().any(|f| f.contains("conflict")));
}

#[tokio::test]
async fn overlapping_edits_create_a_conflict_copy() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("doc.txt", "one\ntwo\nthree\nfour\nfive\n");
    a.sync().await;
    b.sync().await;

    a.write("doc.txt", "one\ntwo\nLAPTOP\nfour\nfive\n");
    b.write("doc.txt", "one\ntwo\nPHONE\nfour\nfive\n");
    a.sync().await; // the laptop reached the server first and keeps the name
    let r = b.sync().await;
    assert_eq!(r.conflicts.len(), 1, "{r:?}");
    let copy = &r.conflicts[0];
    assert!(copy.contains("(conflict – phone – ") && copy.ends_with(".txt"), "{copy}");
    assert!(b.text("doc.txt").contains("LAPTOP"), "the server's version keeps the name");
    assert!(b.text(copy).contains("PHONE"), "the loser's data is preserved");

    a.sync().await;
    b.sync().await;
    assert_same(&a, &b);
    assert!(a.text(copy).contains("PHONE"), "the conflict copy is synced to every device");
    assert_eq!(a.tree().len(), 2);
}

#[tokio::test]
async fn concurrent_binary_edits_never_merge() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("image.bin", [0u8, 1, 2, 3, 0, 5]);
    a.sync().await;
    b.sync().await;
    a.write("image.bin", [0u8, 9, 9, 9, 0, 5]);
    b.write("image.bin", [0u8, 7, 7, 7, 0, 5]);
    a.sync().await;
    let r = b.sync().await;
    assert!(r.merged.is_empty());
    assert_eq!(r.conflicts.len(), 1);
    a.sync().await;
    b.sync().await;
    assert_same(&a, &b);
    assert_eq!(a.read("image.bin"), [0u8, 9, 9, 9, 0, 5]);
    assert_eq!(a.read(&r.conflicts[0]), [0u8, 7, 7, 7, 0, 5]);
}

#[tokio::test]
async fn edit_beats_delete() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("precious.txt", "v1\n");
    a.write("dir/inner.txt", "inner\n");
    a.sync().await;
    b.sync().await;

    fs::remove_file(a.p("precious.txt")).unwrap();
    fs::remove_dir_all(a.p("dir")).unwrap();
    a.sync().await; // deletes both on the server
    b.write("precious.txt", "v1\nedited on the phone\n");
    b.write("dir/inner.txt", "inner\nedited too\n");
    b.sync().await; // the edits must win and the files come back
    b.sync().await;
    a.sync().await;
    assert_eq!(a.text("precious.txt"), "v1\nedited on the phone\n");
    assert_eq!(a.text("dir/inner.txt"), "inner\nedited too\n");
    assert_same(&a, &b);
}

#[tokio::test]
async fn deleting_an_unchanged_file_wins_over_nothing_and_local_delete_loses_to_remote_edit() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("f.txt", "1");
    a.sync().await;
    b.sync().await;
    // a deletes, b edited: b's edit wins (see edit_beats_delete); here the reverse: b deletes, a edited
    fs::remove_file(b.p("f.txt")).unwrap();
    a.write("f.txt", "2-edited-on-laptop");
    a.sync().await;
    b.sync().await;
    assert_eq!(b.text("f.txt"), "2-edited-on-laptop", "a remote edit beats a local delete");
    assert_same(&a, &b);
}

#[tokio::test]
async fn same_new_name_on_both_devices_keeps_both() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("report.txt", "from laptop");
    b.write("report.txt", "from phone");
    a.sync().await;
    let r = b.sync().await;
    assert_eq!(r.conflicts.len(), 1);
    a.sync().await;
    b.sync().await;
    assert_same(&a, &b);
    let all: Vec<String> = a.tree().iter().map(|f| a.text(f)).collect();
    assert!(all.contains(&"from laptop".to_string()) && all.contains(&"from phone".to_string()));
    assert_eq!(a.text("report.txt"), "from laptop");
}

#[tokio::test]
async fn identical_content_on_both_sides_is_adopted_without_conflict() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("same.txt", "identical");
    b.write("same.txt", "identical");
    a.sync().await;
    let r = b.sync().await;
    assert!(r.conflicts.is_empty() && r.uploaded.is_empty(), "{r:?}");
    assert_eq!(a.tree(), vec!["same.txt"]);
}

#[tokio::test]
async fn case_and_unicode_name_collisions_lose_nothing() {
    // Two clients can race and create siblings whose names only differ by case or Unicode normalization.
    // Those are different on Linux but one file on macOS/Windows, so the engine must give every node its
    // own deterministic local name and lose nothing, on any file system.
    let (_srv, user, mut a, mut b) = setup().await;
    user.client.put_file(None, "Readme.md", b"upper").await.unwrap();
    user.client.put_file(None, "readme.md", b"lower").await.unwrap();
    user.client.put_file(None, "cafe\u{301}.txt", b"decomposed").await.unwrap();
    user.client.put_file(None, "caf\u{e9}.txt", b"precomposed").await.unwrap();
    a.sync().await;
    b.sync().await;
    assert_same(&a, &b);
    assert_eq!(a.tree().len(), 4, "{:?}", a.tree());
    let contents: Vec<String> = a.tree().iter().map(|f| a.text(f)).collect();
    for c in ["upper", "lower", "decomposed", "precomposed"] {
        assert!(contents.contains(&c.to_string()), "{c} was lost: {:?}", a.tree());
    }
    // and the naming is stable: nothing is renamed or transferred on later passes
    assert!(a.sync().await.is_empty());
    assert!(b.sync().await.is_empty());
}

#[tokio::test]
async fn unsyncable_names_and_temp_files_are_skipped() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("ok.txt", "ok");
    a.write("bad:name.txt", "colon"); // cannot exist on Windows
    a.write("CON", "reserved");
    a.write(".syncloom-tmp-123", "engine temp");
    let r = a.sync().await;
    assert_eq!(r.uploaded, vec!["ok.txt"]);
    assert_eq!(r.skipped.len(), 2);
    b.sync().await;
    assert_eq!(b.tree(), vec!["ok.txt"]);
}

#[tokio::test]
async fn executable_bit_and_mtime_survive() {
    use std::os::unix::fs::PermissionsExt;
    let (_srv, _u, mut a, mut b) = setup().await;
    a.write("run.sh", "#!/bin/sh\necho hi\n");
    fs::set_permissions(a.p("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    a.sync().await;
    b.sync().await;
    let (ma, mb) = (fs::metadata(a.p("run.sh")).unwrap(), fs::metadata(b.p("run.sh")).unwrap());
    assert_eq!(mb.permissions().mode() & 0o111, 0o111);
    let ms = |t: std::time::SystemTime| t.duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    assert_eq!(ms(ma.modified().unwrap()), ms(mb.modified().unwrap()), "mtime is kept (millisecond precision)");
}

#[tokio::test]
async fn first_sync_into_a_populated_folder_and_many_files() {
    let (_srv, user, mut a, _b) = setup().await;
    for i in 0..60 {
        a.write(&format!("many/dir{}/file{i}.txt", i % 5), format!("content {i}"));
    }
    a.sync().await;
    // a brand-new device whose folder already contains some of the same files
    let mut c = Device::new(&_srv, &user, "tablet").await;
    c.write("many/dir0/file0.txt", "content 0");
    c.write("extra.txt", "only on tablet");
    let r = c.sync().await;
    assert!(r.conflicts.is_empty(), "{r:?}");
    assert_eq!(r.uploaded, vec!["extra.txt"]);
    assert_eq!(c.tree().iter().filter(|f| f.ends_with(".txt")).count(), 61);
    a.sync().await;
    assert_same(&a, &c);
}

#[tokio::test]
async fn restart_resumes_from_saved_state() {
    let srv = start().await;
    let user = new_user(&srv, "alice", None).await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = tempfile::tempdir().unwrap();
    let make = |dir: PathBuf, db: PathBuf| {
        let (base, token, password) = (srv.base.clone(), user.token.clone(), user.password.clone());
        async move {
            let client = Client::connect(&base, &token, &password).await.unwrap();
            SyncEngine::new(Arc::new(client), SyncConfig { root: dir, device: "laptop".into() }, StateDb::open(&db.join("state.db")).unwrap()).unwrap()
        }
    };
    fs::write(dir.path().join("a.txt"), "a").unwrap();
    let mut e = make(dir.path().to_path_buf(), db_path.path().to_path_buf()).await;
    assert_eq!(e.sync_once().await.unwrap().uploaded, vec!["a.txt"]);
    drop(e);
    let mut e = make(dir.path().to_path_buf(), db_path.path().to_path_buf()).await;
    assert!(e.sync_once().await.unwrap().is_empty(), "no re-upload after a restart");
    fs::write(dir.path().join("b.txt"), "b").unwrap();
    assert_eq!(e.sync_once().await.unwrap().uploaded, vec!["b.txt"]);
}

#[tokio::test]
async fn run_loop_reacts_to_server_pushes() {
    let (_srv, _u, mut a, mut b) = setup().await;
    a.sync().await;
    b.sync().await;
    let root = b.dir.path().to_path_buf();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        // a long poll interval: only the gRPC push can wake this up in time
        b.engine.run(stop_rx, Duration::from_secs(120), |_| {}).await.unwrap();
        b
    });
    tokio::time::sleep(Duration::from_millis(800)).await;
    a.write("pushed.txt", "live!");
    a.sync().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !root.join("pushed.txt").exists() {
        assert!(std::time::Instant::now() < deadline, "file did not arrive via push");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(fs::read_to_string(root.join("pushed.txt")).unwrap(), "live!");
    stop_tx.send(true).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn moving_files_between_folders_keeps_the_node() {
    let (srv, user, mut a, mut b) = setup().await;
    a.write("inbox/report.txt", "quarterly");
    a.write("inbox/keep.txt", "keep");
    fs::create_dir_all(a.p("done")).unwrap();
    a.sync().await;
    b.sync().await;
    let node_before = Client::connect(&srv.base, &user.token, &user.password).await.unwrap();
    let id_before = node_before.list(None).await.unwrap().into_iter().find(|n| n.name == "inbox").map(|n| n.id).unwrap();
    let report_id = node_before.list(Some(&id_before)).await.unwrap().into_iter().find(|n| n.name == "report.txt").unwrap().id;

    // move into an existing folder, and rename at the same time
    fs::rename(a.p("inbox/report.txt"), a.p("done/Q3 report.txt")).unwrap();
    // and into a folder that did not exist before
    fs::create_dir_all(a.p("brand/new")).unwrap();
    fs::rename(a.p("inbox/keep.txt"), a.p("brand/new/keep.txt")).unwrap();
    let r = a.sync().await;
    assert!(r.moved.contains(&"done/Q3 report.txt".to_string()) && r.moved.contains(&"brand/new/keep.txt".to_string()), "{r:?}");
    assert!(r.trashed_remote.is_empty(), "nothing may be deleted: {r:?}");
    assert!(!r.uploaded.iter().any(|u| u.ends_with(".txt")), "no content is re-uploaded: {r:?}");

    let r = b.sync().await;
    assert!(r.downloaded.is_empty(), "{r:?}");
    assert_eq!(b.text("done/Q3 report.txt"), "quarterly");
    assert_eq!(b.text("brand/new/keep.txt"), "keep");
    assert!(!b.exists("inbox/report.txt"));
    assert_same(&a, &b);
    // the very same node moved, so its identity (history, shares, links) is intact
    let moved = node_before.get(&report_id).await.unwrap();
    assert_eq!(moved.name, "Q3 report.txt");
    assert_eq!(node_before.versions(&report_id).await.unwrap().len(), 1);
}
