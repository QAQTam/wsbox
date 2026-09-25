//! End-to-end tests for the properties the engine exists to guarantee.
//!
//! The overlay tests need unprivileged user namespaces plus overlayfs. Rather
//! than silently passing on a host that cannot provide them, they assert that
//! the capability probe *agrees* with reality and skip with a printed reason —
//! a test that cannot fail is worse than no test.

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;

use tempfile::TempDir;
use wsbox::protocol::{ExecParams, LedgerQueryParams, Mode, Network, Op, SessionOpenParams, Spec};
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
    exec_with(session, call, script, Vec::new())
}

fn exec_with(
    session: &mut Session,
    call: &str,
    script: &str,
    passthrough: Vec<PathBuf>,
) -> wsbox::protocol::ExecResult {
    session
        .exec(&ExecParams {
            session: session.meta.id.clone(),
            call: call.to_string(),
            cwd: session.meta.workspace.clone(),
            argv: vec!["bash".into(), "-lc".into(), script.to_string()],
            spec: Spec {
                enabled: true,
                writable_roots: vec![session.meta.workspace.clone()],
                passthrough,
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

/// Size and mtime are not the signal; content is. A same-size rewrite must
/// still produce a line-level diff.
#[test]
fn same_size_rewrite_is_reported_with_a_diff() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("same.txt", "aaaa\n");

    let mut session = fixture.open("same-size", Mode::Overlay);
    let result = exec(&mut session, "call-1", "printf 'bbbb\\n' > same.txt");

    assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
    let change = &result.changes[0];
    assert_eq!(change.before_bytes, Some(5));
    assert_eq!(change.after_bytes, Some(5));
    let diff = change.diff.as_deref().expect("a textual diff");
    assert!(diff.contains("-aaaa"), "{diff}");
    assert!(diff.contains("+bbbb"), "{diff}");
}

/// Binary changes still belong in the change set even though there is no
/// textual diff to render.
#[test]
fn binary_change_is_reported_without_a_text_diff() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    std::fs::write(fixture.path("blob.bin"), [0xff, 0xfe, 0xfd, 0xfc]).expect("binary fixture");

    let mut session = fixture.open("binary", Mode::Overlay);
    let result = exec(
        &mut session,
        "call-1",
        "printf '\\377\\376\\375' > blob.bin",
    );

    assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
    let change = &result.changes[0];
    assert_eq!(change.op, Op::Modify);
    assert_eq!(change.before_bytes, Some(4));
    assert_eq!(change.after_bytes, Some(3));
    assert!(change.diff.is_none(), "binary content has no text diff");
    assert_ne!(change.before_sha, change.after_sha);
}

/// A call that returns a path to its baseline state leaves no cumulative
/// change behind. The ledger still records both calls; the session view is the
/// current state, not the union of every transient edit.
#[test]
fn returning_to_the_baseline_clears_the_cumulative_change() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "original\n");

    let mut session = fixture.open("revert-to-baseline", Mode::Overlay);
    exec(&mut session, "call-1", "echo changed > a.txt");
    assert_eq!(session.changes().expect("first changes").len(), 1);

    let result = exec(&mut session, "call-2", "printf 'original\\n' > a.txt");
    assert_eq!(result.changes.len(), 1, "call 2 did change the file");
    assert!(
        session.changes().expect("final changes").is_empty(),
        "a final state equal to the baseline is not a pending change"
    );
}

/// A user permission change during the session must conflict just like a
/// content edit. Hashing only bytes would silently overwrite it.
#[test]
fn apply_aborts_on_a_user_mode_conflict() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("script.sh", "#!/bin/sh\necho hi\n");
    let script = fixture.path("script.sh");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let mut session = fixture.open("mode-conflict", Mode::Overlay);
    exec(&mut session, "call-1", "chmod 755 script.sh");

    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o600))
        .expect("user chmod 600");

    let applied = session.apply(false).expect("apply");
    assert!(!applied.ok, "a mode conflict must abort apply");
    assert_eq!(applied.conflicts, vec!["script.sh"]);
    assert_eq!(
        std::fs::metadata(&script).expect("stat").mode() & 0o7777,
        0o600,
        "the user's mode must survive"
    );
}

/// Replacing a file with a directory is a modify, not a permission change,
/// even when the symlink target and the old file happen to have the same bytes.
#[test]
fn file_to_symlink_with_equal_bytes_is_a_modify() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("path", "target");

    let mut session = fixture.open("type-change", Mode::Overlay);
    let result = exec(&mut session, "call-1", "ln -sfn target path");

    assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
    assert_eq!(
        result.changes[0].op,
        Op::Modify,
        "the file type changed even though the content digest did not"
    );
    assert_eq!(result.changes[0].before_sha, result.changes[0].after_sha);
}

/// `apply` has to replace the path itself, not try to create a directory where
/// a regular file still exists.
#[test]
fn apply_replaces_a_file_with_a_directory() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("node", "old\n");

    let mut session = fixture.open("apply-file-to-dir", Mode::Overlay);
    exec(
        &mut session,
        "call-1",
        "rm node && mkdir node && printf 'inner\\n' > node/file.txt",
    );

    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);
    assert!(fixture.path("node").is_dir());
    assert_eq!(fixture.read("node/file.txt"), "inner\n");
}

/// Restoring a tree added by the session must remove the directories after
/// removing their children; a single forward pass leaves empty directories
/// behind that the next call would report as new again.
#[test]
fn restore_removes_an_added_directory_tree() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("keep.txt", "keep\n");

    let mut session = fixture.open("restore-added-tree", Mode::Overlay);
    exec(
        &mut session,
        "call-1",
        "mkdir -p nested/deep && printf 'x\\n' > nested/deep/file.txt",
    );

    session.restore(None, true).expect("restore all");
    assert!(
        !session.root.join("upper/nested").exists(),
        "the added directory tree must be removed from the session view"
    );
    assert!(session.changes().expect("changes").is_empty());
}

/// Restoring a file that the session replaced with a directory must remove the
/// directory tree before materialising the baseline file.
#[test]
fn restore_replaces_a_directory_with_its_baseline_file() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("path", "baseline\n");

    let mut session = fixture.open("restore-file-from-dir", Mode::Overlay);
    exec(
        &mut session,
        "call-1",
        "rm path && mkdir path && printf 'inner\\n' > path/file.txt",
    );

    session.restore(None, true).expect("restore all");
    assert_eq!(
        std::fs::read_to_string(session.root.join("upper/path")).expect("restored file"),
        "baseline\n"
    );
    assert!(session.changes().expect("changes").is_empty());
}

/// On Unix, backslash is an ordinary filename byte, not a separator. Replacing
/// it with `/` invents a path that does not exist and makes `apply` fail.
#[test]
fn a_backslash_in_a_filename_is_not_a_directory_separator() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("keep.txt", "keep\n");

    let mut session = fixture.open("backslash-path", Mode::Overlay);
    let result = exec(&mut session, "call-1", r#"printf 'x\n' > 'back\slash.txt'"#);

    assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
    assert_eq!(result.changes[0].path, r"back\slash.txt");
    assert!(
        result.changes[0]
            .diff
            .as_deref()
            .is_some_and(|diff| diff.contains("+x")),
        "the invented path has no content to diff"
    );

    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);
    assert_eq!(fixture.read(r"back\slash.txt"), "x\n");
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

/* --------------------------------- audit -------------------------------- */

#[test]
fn ledger_query_filters_by_call_and_path() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    fixture.write("b.txt", "two\n");

    let mut session = fixture.open("query", Mode::Overlay);
    exec(&mut session, "call-a", "echo x > a.txt");
    exec(&mut session, "call-b", "echo y > b.txt");

    let by_call = session
        .query_ledger(&LedgerQueryParams {
            session: session.meta.id.clone(),
            ledger_dir: None,
            call: Some("call-a".into()),
            path: None,
            since_seq: None,
            limit: None,
        })
        .expect("query by call");
    assert_eq!(by_call.total, 1);
    assert_eq!(by_call.ledger_entries, 2);
    assert_eq!(by_call.entries[0].call, "call-a");

    let by_path = session
        .query_ledger(&LedgerQueryParams {
            session: session.meta.id.clone(),
            ledger_dir: None,
            call: None,
            path: Some("b.txt".into()),
            since_seq: None,
            limit: None,
        })
        .expect("query by path");
    assert_eq!(by_path.total, 1);
    assert_eq!(by_path.entries[0].call, "call-b");

    // Newest first, and `total` still reports the full match count.
    let limited = session
        .query_ledger(&LedgerQueryParams {
            session: session.meta.id.clone(),
            ledger_dir: None,
            call: None,
            path: None,
            since_seq: None,
            limit: Some(1),
        })
        .expect("query limited");
    assert_eq!(limited.total, 2);
    assert_eq!(limited.entries.len(), 1);
    assert_eq!(limited.entries[0].call, "call-b");
}

/// Retention must never cost the audit trail, only the ability to
/// re-materialise an old state.
#[test]
fn history_survives_pruning() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "v0\n");

    let mut session = fixture.open("prune", Mode::Overlay);
    for index in 1..=6 {
        exec(
            &mut session,
            &format!("call-{index}"),
            &format!("echo v{index} > a.txt"),
        );
    }

    let before = session.history("a.txt").expect("history");
    assert_eq!(before.versions.len(), 6);
    assert!(before.baseline_available, "the baseline is never evicted");
    assert!(
        before.versions.iter().all(|v| v.after_available),
        "nothing has been pruned yet"
    );

    let gc = session.gc(1, false).expect("gc");
    assert!(gc.pruned > 0, "gc should have reclaimed something");

    let after = session.history("a.txt").expect("history");
    assert_eq!(
        after.versions.len(),
        6,
        "pruning content must not delete the record of what happened"
    );
    assert!(
        after.baseline_available,
        "the baseline must survive gc unconditionally"
    );
    assert!(
        after.versions.iter().any(|v| !v.after_available),
        "old intermediates should be gone"
    );
    assert!(
        after.versions.last().unwrap().after_available,
        "the current state must survive gc"
    );
}

/// The two guarantees gc must not break: applying the current state, and
/// restoring to the baseline.
#[test]
fn gc_keeps_restore_and_apply_working() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    let original = large_file(200);
    fixture.write("a.txt", &original);

    let mut session = fixture.open("gc-safe", Mode::Overlay);
    for index in 1..=5 {
        exec(
            &mut session,
            &format!("call-{index}"),
            &format!("echo version-{index} > a.txt"),
        );
    }

    let gc = session.gc(1, false).expect("gc");
    assert!(gc.pruned > 0);

    // The ledger chain is untouched by gc.
    assert_eq!(
        wsbox::ledger::verify(&session.ledger_path()).expect("verify"),
        5
    );

    // Apply still works: the current state is protected.
    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);
    assert_eq!(fixture.read("a.txt"), "version-5\n");

    // Restore still works: the baseline is protected. In overlay mode this
    // rewrites `upper/`, i.e. what the sandbox sees — the real workspace keeps
    // the applied state until the session is discarded.
    session.restore(Some("a.txt"), false).expect("restore");
    let upper = session.root.join("upper").join("a.txt");
    assert_eq!(
        std::fs::read_to_string(&upper).expect("upper"),
        original,
        "restore must put the sandbox view back to the baseline"
    );
    assert!(
        session.changes().expect("changes").is_empty(),
        "a restored path drops out of the change set"
    );
}

/// Content addressing must not store the same bytes twice.
#[test]
fn identical_content_is_stored_once() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    let shared = "the same content in both files\n".repeat(100);
    fixture.write("a.txt", &shared);
    fixture.write("b.txt", &shared);

    let mut session = fixture.open("dedupe", Mode::Overlay);
    exec(
        &mut session,
        "call-1",
        "echo extra >> a.txt; echo extra >> b.txt",
    );

    let blobs = session.cas.iter().expect("cas");
    let digests: std::collections::BTreeSet<&String> =
        blobs.iter().map(|(sha, _, _)| sha).collect();
    assert_eq!(
        digests.len(),
        blobs.len(),
        "the CAS must never hold two blobs with the same digest"
    );

    // a.txt and b.txt had identical baselines and identical results, so the two
    // files contribute exactly two distinct blobs between them.
    assert!(
        blobs.len() <= 4,
        "expected deduplication, found {} blobs",
        blobs.len()
    );
}

/// A large file rewritten with distinct content every call is the worst case
/// for content addressing. This is the case retention exists for.
#[test]
fn repeated_rewrites_are_bounded_by_gc() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("big.txt", &"x".repeat(200_000));

    let mut session = fixture.open("growth", Mode::Overlay);
    for index in 1..=8 {
        exec(
            &mut session,
            &format!("call-{index}"),
            &format!("python3 -c \"open('big.txt','w').write('v{index}'*100000)\""),
        );
    }

    let before = session.status().expect("status");
    assert!(
        before.cas_bytes > 1_000_000,
        "eight distinct 200 KB versions plus the baseline should exceed 1 MB, got {}",
        before.cas_bytes
    );

    session.gc(2, false).expect("gc");

    let after = session.status().expect("status");
    assert!(
        after.cas_bytes < before.cas_bytes / 2,
        "gc should reclaim most of the intermediate versions: {} -> {}",
        before.cas_bytes,
        after.cas_bytes
    );
    assert_eq!(
        after.ledger_entries, before.ledger_entries,
        "gc must not touch the ledger"
    );
    assert_eq!(
        after.changed_paths, before.changed_paths,
        "gc must not change the session's change set"
    );
}

/* --------------------------- selective passthrough ---------------------- */

/// Build output should land on the real disk and stay out of the change set —
/// otherwise `cargo build` alone would fill the content store with `target/`.
#[test]
fn passthrough_keeps_build_output_out_of_the_diff() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("src/main.rs", "fn main() { println!(\"hi\"); }\n");
    let target = fixture.path("target");

    let mut session = fixture.open("passthrough", Mode::Overlay);
    let result = exec_with(
        &mut session,
        "call-1",
        "mkdir -p target/debug && head -c 50000 /dev/zero > target/debug/artifact.o \
         && sed -i 's/hi/hello/' src/main.rs",
        vec![target.clone()],
    );

    // The build output is really on disk...
    assert!(
        target.join("debug/artifact.o").is_file(),
        "passthrough writes must reach the real filesystem"
    );
    // ...and never entered the overlay, so it is not in the change set.
    let paths: Vec<&str> = result.changes.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths,
        vec!["src/main.rs"],
        "build output leaked into the diff"
    );

    // The source edit is still journaled and still recoverable.
    assert!(
        fixture.read("src/main.rs").contains("hi"),
        "the real source file must be untouched"
    );
    assert!(result.changes[0].diff.as_deref().unwrap().contains("hello"));

    // The declaration itself is part of the audit record.
    let ledger = session
        .query_ledger(&LedgerQueryParams {
            session: session.meta.id.clone(),
            ledger_dir: None,
            call: None,
            path: None,
            since_seq: None,
            limit: None,
        })
        .expect("query");
    assert_eq!(
        ledger.entries[0].passthrough,
        vec![target.display().to_string()]
    );
}

#[test]
fn passthrough_outside_the_workspace_is_rejected() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    let mut session = fixture.open("passthrough-escape", Mode::Overlay);

    let result = session.exec(&ExecParams {
        session: session.meta.id.clone(),
        call: "call-1".into(),
        cwd: session.meta.workspace.clone(),
        argv: vec!["true".into()],
        spec: Spec {
            enabled: true,
            writable_roots: vec![session.meta.workspace.clone()],
            passthrough: vec![PathBuf::from("/etc")],
            network: Network::Deny,
            ..Spec::default()
        },
        ledger_dir: None,
        timeout_ms: Some(10_000),
        max_output_bytes: None,
    });

    assert!(
        result.is_err(),
        "a passthrough path outside the workspace must be refused"
    );
}

/// `--passthrough ../elsewhere` is the same escape with a relative path: the
/// joined result is lexically inside the workspace and really outside it. It
/// must be refused *before* the directory is created, or the check itself
/// leaves a footprint outside the workspace.
#[test]
fn passthrough_cannot_escape_with_a_parent_dir() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    let mut session = fixture.open("passthrough-parent", Mode::Overlay);

    // Resolved exactly the way the CLI resolves a relative --passthrough.
    let unique = fixture
        .ledger
        .path()
        .file_name()
        .expect("ledger dir name")
        .to_string_lossy()
        .to_string();
    let escape = session
        .meta
        .workspace
        .join(format!("../wsbox-escape-{unique}"));
    let result = session.exec(&ExecParams {
        session: session.meta.id.clone(),
        call: "call-1".into(),
        cwd: session.meta.workspace.clone(),
        argv: vec!["true".into()],
        spec: Spec {
            enabled: true,
            writable_roots: vec![session.meta.workspace.clone()],
            passthrough: vec![escape.clone()],
            network: Network::Deny,
            ..Spec::default()
        },
        ledger_dir: None,
        timeout_ms: Some(10_000),
        max_output_bytes: None,
    });

    assert!(result.is_err(), "`..` in a passthrough must be refused");
    assert!(
        !escape.exists(),
        "a refused passthrough must not create the directory it named"
    );
}

#[test]
fn git_cannot_be_a_passthrough_path() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    std::fs::create_dir_all(fixture.path(".git")).expect("git dir");
    let mut session = fixture.open("passthrough-git", Mode::Overlay);

    let result = session.exec(&ExecParams {
        session: session.meta.id.clone(),
        call: "call-1".into(),
        cwd: session.meta.workspace.clone(),
        argv: vec!["true".into()],
        spec: Spec {
            enabled: true,
            writable_roots: vec![session.meta.workspace.clone()],
            passthrough: vec![fixture.path(".git")],
            network: Network::Deny,
            ..Spec::default()
        },
        ledger_dir: None,
        timeout_ms: Some(10_000),
        max_output_bytes: None,
    });

    assert!(
        result.is_err(),
        "`.git` must never bypass the journal, or history can be rewritten unseen"
    );
}

/// A fifo is a real file a build script may create. Reporting it and then
/// silently not applying it made `apply` claim success for a change it had not
/// made.
#[test]
fn a_fifo_is_applied_as_a_fifo() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    let mut session = fixture.open("fifo", Mode::Overlay);

    let result = exec(&mut session, "call-1", "mkfifo pipe");
    assert_eq!(result.changes.len(), 1);
    assert_eq!(result.changes[0].path, "pipe");

    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);
    let metadata = std::fs::symlink_metadata(fixture.path("pipe")).expect("the fifo exists");
    assert!(
        metadata.file_type().is_fifo(),
        "apply must create a fifo, not a regular file"
    );
}

/// A session id becomes a directory name under the ledger root, so it must not
/// be able to navigate out of it.
#[test]
fn a_session_id_cannot_escape_the_ledger_directory() {
    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    let unique = fixture
        .ledger
        .path()
        .file_name()
        .expect("ledger dir name")
        .to_string_lossy()
        .to_string();
    let escaped = format!("wsbox-escape-{unique}");

    let result = Session::open(&SessionOpenParams {
        session: format!("../../{escaped}"),
        workspace: fixture.workspace.path().to_path_buf(),
        ledger_dir: Some(fixture.ledger.path().to_path_buf()),
        mode: Mode::Snapshot,
        copy_mode: Default::default(),
    });

    assert!(result.is_err(), "a session id must not escape the ledger");
    assert!(
        !fixture
            .ledger
            .path()
            .parent()
            .expect("ledger parent")
            .join(&escaped)
            .exists(),
        "a rejected session id must not create anything"
    );
}

/* ------------------------------ structural ------------------------------ */

/// overlayfs materialises a directory in `upper/` as soon as anything inside it
/// is copied up. That is not a change the caller asked for.
#[test]
fn copying_up_a_directory_is_not_reported_as_a_change() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("src/main.rs", "one\n");
    fixture.write("src/lib.rs", "two\n");

    let mut session = fixture.open("dirs", Mode::Overlay);
    let result = exec(&mut session, "call-1", "echo changed > src/main.rs");

    let paths: Vec<&str> = result.changes.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths,
        vec!["src/main.rs"],
        "the parent directory is structural"
    );
}

/// A genuinely new directory is a change, and `apply` has to reproduce it.
#[test]
fn a_new_directory_is_applied() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");

    let mut session = fixture.open("new-dir", Mode::Overlay);
    exec(
        &mut session,
        "call-1",
        "mkdir -p nested/deep && echo x > nested/deep/b.txt",
    );

    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);
    assert_eq!(fixture.read("nested/deep/b.txt"), "x\n");
}

/// Deleting an existing directory produces a whiteout for the directory itself,
/// not individual entries for files the overlay never copied up. The baseline
/// side therefore has to represent directories as existing states, or `rm -rf`
/// silently produces no change at all.
#[test]
fn deleting_a_directory_is_reported_and_applied() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("nested/deep/file.txt", "x\n");

    let mut session = fixture.open("delete-dir", Mode::Overlay);
    let result = exec(&mut session, "call-1", "rm -rf nested");

    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    let change = result
        .changes
        .iter()
        .find(|change| change.path == "nested")
        .unwrap_or_else(|| panic!("directory deletion missing from {:?}", result.changes));
    assert_eq!(change.op, Op::Delete);
    assert!(change.reversible, "the lower directory must be restorable");

    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);
    assert!(
        !fixture.path("nested").exists(),
        "apply must remove the directory, not just its tracked children"
    );
}

/// A baseline file replaced by an *empty* directory has no child file whose
/// addition can implicitly recreate the directory. The directory transition
/// itself has to be a reported change.
#[test]
fn replacing_a_file_with_an_empty_directory_is_reported() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("node", "old\n");

    let mut session = fixture.open("empty-file-to-dir", Mode::Overlay);
    let result = exec(&mut session, "call-1", "rm node && mkdir node");

    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
    assert_eq!(result.changes[0].path, "node");
    assert_eq!(result.changes[0].op, Op::Modify);

    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);
    assert!(fixture.path("node").is_dir());
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

/* ------------------------------ output capture -------------------------- */

/// A capped stream must point at a file that exists and holds the full output.
#[test]
fn a_truncated_stream_spills_to_a_real_file() {
    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    let mut session = fixture.open("spill", Mode::Snapshot);

    let result = session
        .exec(&ExecParams {
            session: session.meta.id.clone(),
            call: "call-1".into(),
            cwd: session.meta.workspace.clone(),
            argv: vec![
                "bash".into(),
                "-lc".into(),
                "python3 -c \"import sys; sys.stdout.write('x' * 4000)\"".into(),
            ],
            // No sandbox: this test is about the capture, not the isolation.
            spec: Spec {
                enabled: false,
                ..Spec::default()
            },
            ledger_dir: None,
            timeout_ms: Some(30_000),
            max_output_bytes: Some(1024),
        })
        .expect("exec");

    assert_eq!(result.stdout_bytes, 4000, "the real byte count is reported");
    assert!(
        result.stdout.contains("omitted"),
        "the inline text says it was capped"
    );

    let spill = result
        .stdout_spill
        .clone()
        .expect("a capped stream has a spill path");
    assert!(
        spill.is_file(),
        "the spill path must exist: {}",
        spill.display()
    );
    let full = std::fs::read(&spill).expect("read the spill file");
    assert_eq!(full.len() as u64, result.stdout_bytes);
    assert!(
        result.stdout.len() < full.len(),
        "the inline copy must be shorter than the file"
    );
}

/// A command is free to exit 125 — plenty do. Treating that as a sandbox setup
/// failure discarded the entire change set of a command that had already
/// written to the workspace, which is the exact failure mode this engine
/// exists to prevent.
#[test]
fn a_command_exiting_125_still_reports_its_changes() {
    let fixture = Fixture::new();
    fixture.write("a.txt", "one\n");
    let mut session = fixture.open("exit-125", Mode::Snapshot);

    let result = session
        .exec(&ExecParams {
            session: session.meta.id.clone(),
            call: "call-1".into(),
            cwd: session.meta.workspace.clone(),
            argv: vec![
                "bash".into(),
                "-lc".into(),
                "echo changed > a.txt; exit 125".into(),
            ],
            spec: Spec {
                enabled: false,
                ..Spec::default()
            },
            ledger_dir: None,
            timeout_ms: Some(30_000),
            max_output_bytes: None,
        })
        .expect("a command exit is not a sandbox error");

    assert_eq!(result.exit_code, 125);
    assert_eq!(result.changes.len(), 1, "the write must still be reported");
    assert_eq!(result.changes[0].path, "a.txt");
    assert!(
        result.changes[0]
            .diff
            .as_deref()
            .is_some_and(|diff| diff.contains("+changed")),
        "the diff must show what the command wrote"
    );
}

/* ------------------------- symlinks and permissions --------------------- */
/// A symlink is a file whose content is its target. Journaling it as one means
/// `apply` can recreate the link, and retargeting it is a visible change rather
/// than a silent one.
#[test]
fn a_symlink_is_journaled_and_applied() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("real.txt", "content\n");
    let mut session = fixture.open("symlink", Mode::Overlay);

    let created = exec(&mut session, "call-1", "ln -s real.txt link");
    assert_eq!(created.changes.len(), 1);
    assert_eq!(created.changes[0].op, Op::Add);
    assert!(
        std::fs::symlink_metadata(fixture.path("link")).is_err(),
        "the real workspace must not have the link before `apply`"
    );

    // Retargeting the link changes its content, so it has to be reported. A
    // symlink whose bytes are never read is invisible here.
    let retargeted = exec(&mut session, "call-2", "ln -sfn other.txt link");
    assert_eq!(
        retargeted.changes.len(),
        1,
        "retargeting a symlink must be a change"
    );
    assert_eq!(retargeted.changes[0].op, Op::Modify);

    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);
    assert_eq!(
        std::fs::read_link(fixture.path("link")).expect("link exists after apply"),
        PathBuf::from("other.txt")
    );
}

/// A pre-existing symlink makes the conflict check compare link *targets*: the
/// digest recorded for a link is its target, so hashing what it points at would
/// report a conflict for every link the session touched.
#[test]
fn a_retargeted_symlink_applies_and_a_user_edit_conflicts() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("real.txt", "content\n");
    fixture.write("other.txt", "content\n");
    fixture.write("third.txt", "content\n");
    std::os::unix::fs::symlink("real.txt", fixture.path("link")).expect("baseline link");

    let mut session = fixture.open("symlink-apply", Mode::Overlay);
    exec(&mut session, "call-1", "ln -sfn other.txt link");
    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "unexpected conflicts: {:?}", applied.conflicts);
    assert_eq!(
        std::fs::read_link(fixture.path("link")).expect("link"),
        PathBuf::from("other.txt")
    );

    // The same change, but this time a person moved the link first.
    std::fs::remove_file(fixture.path("link")).expect("clear the applied link");
    std::os::unix::fs::symlink("real.txt", fixture.path("link")).expect("reset link");
    let mut second = fixture.open("symlink-conflict", Mode::Overlay);
    exec(&mut second, "call-1", "ln -sfn other.txt link");
    std::fs::remove_file(fixture.path("link")).expect("user moves the link");
    std::os::unix::fs::symlink("third.txt", fixture.path("link")).expect("user edit");

    let conflicted = second.apply(false).expect("apply");
    assert!(!conflicted.ok, "a user edit to the link must be a conflict");
    assert_eq!(conflicted.conflicts, vec!["link".to_string()]);
}

/// A mode-only change has identical bytes on both sides, which is exactly the
/// case a content-only comparison drops. It has to be reported *and* applied.
#[test]
fn a_mode_change_is_journaled_and_applied() {
    let fixture = Fixture::new();
    fixture.write("script.sh", "#!/bin/sh\necho hi\n");
    let script = fixture.path("script.sh");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let mut session = fixture.open("chmod", Mode::Overlay);
    let result = exec(&mut session, "call-1", "chmod 755 script.sh");

    assert_eq!(result.changes.len(), 1, "a chmod must be reported");
    assert_eq!(result.changes[0].op, Op::Chmod);
    assert_eq!(
        std::fs::metadata(&script).expect("stat").mode() & 0o7777,
        0o644,
        "the real workspace must not be written before `apply`"
    );

    let applied = session.apply(false).expect("apply");
    assert!(applied.ok, "{:?}", applied.conflicts);
    assert_eq!(
        std::fs::metadata(&script).expect("stat").mode() & 0o7777,
        0o755,
        "apply must reproduce the mode, not only the bytes"
    );
}

/// Snapshot mode diffs the live tree, so a mode change has to be caught there
/// too — the bug this pins was in the shared comparison, not in the overlay.
#[test]
fn snapshot_mode_reports_a_mode_change() {
    let fixture = Fixture::new();
    fixture.write("script.sh", "#!/bin/sh\necho hi\n");
    let script = fixture.path("script.sh");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let mut session = fixture.open("chmod-snapshot", Mode::Snapshot);
    let result = exec(&mut session, "call-1", "chmod 755 script.sh");

    assert_eq!(result.changes.len(), 1, "a chmod must be reported");
    assert_eq!(result.changes[0].op, Op::Chmod);
    assert_eq!(
        std::fs::metadata(&script).expect("stat").mode() & 0o7777,
        0o755
    );
}

/// `restore` has to put the permission bits back too, not just the bytes.
#[test]
fn restore_puts_a_mode_back() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("script.sh", "#!/bin/sh\necho hi\n");
    let script = fixture.path("script.sh");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");

    let mut session = fixture.open("chmod-restore", Mode::Overlay);
    exec(&mut session, "call-1", "chmod 600 script.sh");
    assert_eq!(
        exec(&mut session, "check", "stat -c %a script.sh")
            .stdout
            .trim(),
        "600",
        "the sandbox view must carry the new mode"
    );

    session.restore(None, true).expect("restore");

    // The real workspace was never touched, so it still has the baseline mode;
    // what has to be true is that the *session view* went back.
    assert_eq!(
        exec(&mut session, "check-2", "stat -c %a script.sh")
            .stdout
            .trim(),
        "755",
        "restore must reproduce the baseline mode, not only the bytes"
    );
    assert!(
        session.changes().expect("changes").is_empty(),
        "restoring must clear the recorded change"
    );
    assert_eq!(
        std::fs::metadata(&script).expect("stat").mode() & 0o7777,
        0o755
    );
}

/// Restoring an added symlink has to remove it from the view, and restoring a
/// retargeted one has to put the original target back.
#[test]
fn restore_puts_a_symlink_back() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("real.txt", "content\n");
    fixture.write("other.txt", "content\n");
    std::os::unix::fs::symlink("real.txt", fixture.path("link")).expect("baseline link");
    let mut session = fixture.open("symlink-restore", Mode::Overlay);

    exec(&mut session, "call-1", "ln -sfn other.txt link");
    assert_eq!(
        exec(&mut session, "check", "readlink link").stdout.trim(),
        "other.txt"
    );

    session.restore(None, true).expect("restore");
    assert_eq!(
        exec(&mut session, "check-2", "readlink link").stdout.trim(),
        "real.txt",
        "restore must recreate the link, not a file holding its target"
    );
    assert_eq!(
        std::fs::read_link(fixture.path("link")).expect("the real link is untouched"),
        PathBuf::from("real.txt")
    );
}

/// A symlink the session created is not in the baseline, so restoring means
/// removing it again.
#[test]
fn restore_removes_an_added_symlink() {
    if !overlay_available() {
        skip("overlayfs unavailable in a user namespace");
        return;
    }

    let fixture = Fixture::new();
    fixture.write("real.txt", "content\n");
    let mut session = fixture.open("symlink-added-restore", Mode::Overlay);

    exec(&mut session, "call-1", "ln -s real.txt link");
    assert_eq!(
        exec(&mut session, "check", "readlink link").stdout.trim(),
        "real.txt"
    );

    session.restore(None, true).expect("restore");
    assert_eq!(
        exec(
            &mut session,
            "check-2",
            "test -L link && echo yes || echo no"
        )
        .stdout
        .trim(),
        "no",
        "restoring an added link must remove it"
    );
    assert!(
        std::fs::symlink_metadata(fixture.path("link")).is_err(),
        "the real workspace is still untouched"
    );
}
