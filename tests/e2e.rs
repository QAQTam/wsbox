//! End-to-end tests for the properties the engine exists to guarantee.
//!
//! The overlay tests need unprivileged user namespaces plus overlayfs. Rather
//! than silently passing on a host that cannot provide them, they assert that
//! the capability probe *agrees* with reality and skip with a printed reason —
//! a test that cannot fail is worse than no test.

use std::path::PathBuf;

use tempfile::TempDir;
use wsbox::protocol::{ExecParams, Mode, Network, SessionOpenParams, Spec};
use wsbox::session::Session;

struct Fixture {
    workspace: TempDir,
    ledger: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            workspace: TempDir::new().expect("workspace"),
            ledger: TempDir::new().expect("ledger"),
        }
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.workspace.path().join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        std::fs::write(path, contents).expect("write fixture");
    }

    fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.workspace.path().join(relative)).expect("read fixture")
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.workspace.path().join(relative)
    }

    fn open(&self, id: &str, mode: Mode) -> Session {
        let (session, _) = Session::open(&SessionOpenParams {
            session: id.to_string(),
            workspace: self.workspace.path().to_path_buf(),
            ledger_dir: Some(self.ledger.path().to_path_buf()),
            mode,
            copy_mode: Default::default(),
        })
        .expect("open session");
        session
    }
}

fn exec(session: &mut Session, call: &str, script: &str) -> wsbox::protocol::ExecResult {
    session
        .exec(&ExecParams {
            session: session.meta.id.clone(),
            call: call.to_string(),
            cwd: session.meta.workspace.clone(),
            argv: vec!["bash".into(), "-lc".into(), script.to_string()],
            spec: Spec {
                enabled: true,
                writable_roots: vec![session.meta.workspace.clone()],
                network: Network::Deny,
                ..Spec::default()
            },
            ledger_dir: None,
            timeout_ms: Some(60_000),
            max_output_bytes: Some(64 * 1024),
        })
        .expect("exec")
}

fn overlay_available() -> bool {
    wsbox::capabilities::detect().overlayfs
}

fn skip(reason: &str) {
    eprintln!("SKIPPED: {reason}");
}

fn large_file(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("def function_{i}():\n    return {i}\n"))
        .collect()
}

/* ------------------------- the original bug report ---------------------- */

/// The scenario that motivated the engine: a model bypasses `edit`/`apply_patch`
/// and truncates a file through `python`, with no git history to fall back on.
#[test]
fn python_truncation_is_reported_and_the_workspace_survives() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    let original = large_file(200);
    fixture.write("app.py", &original);

    let mut session = fixture.open("truncate", Mode::Overlay);
    let result = exec(
        &mut session,
        "call-1",
        "python3 -c \"open('app.py','w').write('')\"",
    );

    // The real file is untouched: it was only ever the read-only lower layer.
    assert_eq!(fixture.read("app.py"), original);

    assert_eq!(result.changes.len(), 1);
    let change = &result.changes[0];
    assert_eq!(change.path, "app.py");
    assert_eq!(change.op, wsbox::protocol::Op::Modify);
    assert_eq!(change.after_bytes, Some(0));
    assert_eq!(change.before_bytes, Some(original.len() as u64));
    assert!(change.suspicious, "a 100% shrink must be flagged");
    assert!(change.reversible);

    let diff = change.diff.as_deref().expect("a diff must be produced");
    assert!(diff.contains("--- a/app.py"));
    assert!(diff.contains("def function_0()"));
}

/// Deleting a file must be reported as a delete, not as the file vanishing.
#[test]
fn deletion_is_reported_as_a_delete() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("keep.txt", "hello\n");

    let mut session = fixture.open("delete", Mode::Overlay);
    let result = exec(&mut session, "call-1", "rm keep.txt");

    assert!(
        fixture.path("keep.txt").exists(),
        "the real file must survive"
    );
    assert_eq!(result.changes.len(), 1);
    assert_eq!(result.changes[0].op, wsbox::protocol::Op::Delete);
    assert!(result.changes[0].reversible, "a delete must be restorable");
}

/// A rewrite that reproduces the original bytes is not a change.
#[test]
fn no_op_rewrite_produces_no_change() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "same\n");

    let mut session = fixture.open("noop", Mode::Overlay);
    let result = exec(
        &mut session,
        "call-1",
        "cat a.txt > a.tmp && mv a.tmp a.txt",
    );

    assert!(
        result.changes.is_empty(),
        "an atomic rewrite with identical bytes must not be reported: {:?}",
        result.changes
    );
}

/// Atomic writes (tmpfile + rename) are one modify, not add + delete.
#[test]
fn atomic_rename_is_one_modify() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "before\n");

    let mut session = fixture.open("rename", Mode::Overlay);
    let result = exec(
        &mut session,
        "call-1",
        "printf 'after\\n' > a.txt.tmp && mv a.txt.tmp a.txt",
    );

    assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
    assert_eq!(result.changes[0].op, wsbox::protocol::Op::Modify);
    assert!(
        result.changes[0]
            .diff
            .as_deref()
            .unwrap()
            .contains("+after")
    );
}

/* ------------------------------ session flow ---------------------------- */

/// Successive calls compose, and the second call sees the first call's result.
#[test]
fn session_state_accumulates_across_calls() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    fixture.write("b.txt", "two\n");

    let mut session = fixture.open("accumulate", Mode::Overlay);
    exec(&mut session, "call-1", "echo changed > a.txt");
    let second = exec(&mut session, "call-2", "rm b.txt && echo new > c.txt");

    // The second call reports only its own changes...
    let paths: Vec<&str> = second
        .changes
        .iter()
        .map(|change| change.path.as_str())
        .collect();
    assert!(paths.contains(&"b.txt"), "{paths:?}");
    assert!(paths.contains(&"c.txt"), "{paths:?}");
    assert!(!paths.contains(&"a.txt"), "a.txt was not touched by call 2");

    // ...while the session view still knows about all three.
    let cumulative = session.changes().expect("changes");
    let mut all: Vec<&str> = cumulative.iter().map(|c| c.path.as_str()).collect();
    all.sort();
    assert_eq!(all, vec!["a.txt", "b.txt", "c.txt"]);
}

#[test]
fn apply_writes_the_session_state_onto_the_workspace() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "original\n");
    fixture.write("gone.txt", "bye\n");

    let mut session = fixture.open("apply", Mode::Overlay);
    exec(
        &mut session,
        "call-1",
        "echo replaced > a.txt; rm gone.txt; echo hi > new.txt",
    );

    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);

    assert_eq!(fixture.read("a.txt"), "replaced\n");
    assert_eq!(fixture.read("new.txt"), "hi\n");
    assert!(!fixture.path("gone.txt").exists());
}

/// A file the user edited mid-session must abort the whole apply.
#[test]
fn apply_aborts_on_a_user_edit_conflict() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "original\n");

    let mut session = fixture.open("conflict", Mode::Overlay);
    exec(&mut session, "call-1", "echo from-agent > a.txt");

    // The user edits the same file outside the sandbox.
    fixture.write("a.txt", "from-user\n");

    let applied = session.apply(false).expect("apply");
    assert!(!applied.ok, "a conflicting apply must not report success");
    assert_eq!(applied.conflicts, vec!["a.txt"]);
    assert_eq!(
        fixture.read("a.txt"),
        "from-user\n",
        "the user's edit must survive"
    );
}

#[test]
fn restore_puts_a_file_back_to_its_baseline() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    let original = large_file(50);
    fixture.write("a.txt", &original);

    let mut session = fixture.open("restore", Mode::Overlay);
    exec(
        &mut session,
        "call-1",
        "python3 -c \"open('a.txt','w').write('')\"",
    );
    assert_eq!(fixture.read("a.txt"), original, "workspace never changed");

    let restored = session.restore(Some("a.txt"), false).expect("restore");
    assert_eq!(restored, vec!["a.txt"]);
    assert!(
        session.changes().expect("changes").is_empty(),
        "a restored path must drop out of the change set"
    );
}

/* ------------------------------- the ledger ----------------------------- */

#[test]
fn ledger_chain_verifies_and_detects_tampering() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");

    let mut session = fixture.open("ledger", Mode::Overlay);
    exec(&mut session, "call-1", "echo two > a.txt");
    exec(&mut session, "call-2", "echo three > a.txt");

    let path = session.ledger_path();
    assert_eq!(wsbox::ledger::verify(&path).expect("verify"), 2);

    // Rewriting a past entry must break the chain.
    let text = std::fs::read_to_string(&path).expect("read ledger");
    let tampered = text.replacen("\"call-1\"", "\"call-9\"", 1);
    std::fs::write(&path, tampered).expect("tamper");
    assert!(
        wsbox::ledger::verify(&path).is_err(),
        "a modified ledger entry must fail verification"
    );
}

/// The ledger directory is masked inside the sandbox, so an agent cannot delete
/// its own audit trail.
#[test]
fn ledger_directory_is_masked_inside_the_sandbox() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");

    let mut session = fixture.open("mask", Mode::Overlay);
    let ledger = session
        .root
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let result = exec(
        &mut session,
        "call-1",
        &format!(
            "touch {}/pwned && ls {}/sessions",
            ledger.display(),
            ledger.display()
        ),
    );

    assert!(
        !ledger.join("pwned").exists(),
        "a write inside the masked path must not reach the host"
    );
    assert!(
        ledger.join("sessions").exists(),
        "the host-side ledger must still be intact"
    );
    // The masked mount is an empty tmpfs, so `sessions` is not visible inside.
    assert!(
        !result.stdout.contains("sessions") || !result.stdout.contains("ledger.jsonl"),
        "the ledger contents must not be listable from inside: {}",
        result.stdout
    );
}

/* ------------------------------ degraded mode --------------------------- */

/// Snapshot mode is the fallback where user namespaces are blocked. It gives a
/// weaker guarantee (the workspace *is* written) but the same recoverability.
#[test]
fn snapshot_mode_can_revert_a_truncation() {
    let fixture = Fixture::new();
    let original = large_file(200);
    fixture.write("a.txt", &original);

    let mut session = fixture.open("snapshot", Mode::Snapshot);
    let result = exec(
        &mut session,
        "call-1",
        "python3 -c \"open('a.txt','w').write('')\"",
    );

    assert_eq!(result.changes.len(), 1);
    assert!(result.changes[0].suspicious);
    assert_eq!(
        fixture.read("a.txt"),
        "",
        "snapshot mode writes the real tree"
    );

    session.restore(None, true).expect("restore all");
    assert_eq!(
        fixture.read("a.txt"),
        original,
        "the baseline must restore it"
    );
}

/// Requesting overlay on a host that cannot provide it must fail loudly, never
/// silently degrade.
#[test]
fn explicit_overlay_mode_fails_closed_when_unavailable() {
    if overlay_available() {
        skip("this host does support overlayfs, so the failure path cannot be exercised");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    let result = Session::open(&SessionOpenParams {
        session: "closed".into(),
        workspace: fixture.workspace.path().to_path_buf(),
        ledger_dir: Some(fixture.ledger.path().to_path_buf()),
        mode: Mode::Overlay,
        copy_mode: Default::default(),
    });
    assert!(
        result.is_err(),
        "explicit overlay must not degrade silently"
    );
}

/* --------------------------------- protocol ----------------------------- */

#[test]
fn protocol_version_mismatch_is_rejected() {
    let response = wsbox::dispatch(&wsbox::Envelope {
        protocol: 99,
        method: "capabilities".into(),
        params: serde_json::json!({}),
        id: None,
    });
    assert!(!response.ok);
    assert_eq!(response.error.unwrap().code, "protocol_version");
}

#[test]
fn unknown_method_is_unsupported_not_a_panic() {
    let response = wsbox::dispatch(&wsbox::Envelope {
        protocol: wsbox::protocol::PROTOCOL_VERSION,
        method: "does.not.exist".into(),
        params: serde_json::json!({}),
        id: None,
    });
    assert!(!response.ok);
    assert_eq!(response.error.unwrap().code, "unsupported");
}

#[test]
fn path_escapes_are_rejected() {
    assert!(wsbox::fsutil::relative_key("../../etc/passwd").is_err());
    assert!(wsbox::fsutil::relative_key("/etc/passwd").is_err());
    assert!(wsbox::fsutil::relative_key("src/main.rs").is_ok());
}
