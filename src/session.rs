//! Session lifecycle: open, exec, inspect, apply, restore, discard.
//!
//! A session owns a ledger directory and one observation strategy:
//!
//! * `overlay` — the workspace is the read-only lower layer of an overlayfs
//!   mount; every write lands in `upper/`. The real workspace is untouched
//!   until `apply`. This is the strong guarantee.
//! * `snapshot` — a baseline copy is taken once at `open`, then each call diffs
//!   the live tree against it. The workspace *is* written, but every write is
//!   still recoverable. This is what runs where user namespaces are blocked.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cas::Cas;
use crate::diff;
use crate::error::{Error, Result};
use crate::fsutil::{self, Kind, Manifest};
use crate::ledger::{self, Ledger, LedgerChange, LedgerEntry};
use crate::protocol::{
    ApplyResult, Change, ChangeIndex, ExecParams, ExecResult, GcResult, HistoryResult, IndexEntry,
    LedgerQueryParams, LedgerQueryResult, Mode, Op, SessionOpenParams, SessionOpenResult, Spec,
    StatusResult, Version,
};
use crate::sandbox::{OverlayDirs, RunRequest};

/// A file must be at least this large before a shrink is worth flagging.
const SUSPICIOUS_MIN_BYTES: u64 = 1024;
/// ...and must lose this fraction of its content.
const SUSPICIOUS_SHRINK_RATIO: f64 = 0.8;
/// Unified diffs returned inline are capped; the full diff is always on disk.
const MAX_DIFF_BYTES: usize = 64 * 1024;
/// Files larger than this are not read into memory just to render a diff.
///
/// The bytes still reach the CAS — streamed, not buffered — so the change stays
/// reproducible and `apply`/`restore` still work. What is lost is the inline
/// diff, which is why such a change is marked `diffTruncated`: a reviewer must
/// not mistake a partial view for a complete one.
const MAX_INLINE_DIFF_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMeta {
    pub id: String,
    pub workspace: PathBuf,
    pub mode: Mode,
    pub created_ms: u64,
    /// (files, reflinked) from the baseline copy; `None` in overlay mode.
    pub copy_stats: Option<(u64, u64)>,
}

#[derive(Debug)]
pub struct Session {
    pub meta: SessionMeta,
    pub root: PathBuf,
    pub cas: Cas,
    pub index: ChangeIndex,
    ledger: Ledger,
}

/// Exclusive lock over a session's mutable state.
///
/// `index.json` is a read-modify-write file and `ledger.jsonl` carries a hash
/// chain whose next `seq`/`prev` come from the last line on disk, so two `exec`
/// calls in parallel would lose an index update and write two entries claiming
/// the same position in the chain. Holding this for the whole of a mutating
/// operation serialises them; the state is re-read after acquiring it, so the
/// second writer extends the first rather than clobbering it.
///
/// `flock` is advisory and per open-file-description, which is what makes it
/// work between processes and between threads of one process — each `acquire`
/// opens its own description. It is released when the guard drops.
#[derive(Debug)]
pub struct SessionLock {
    file: std::fs::File,
}

impl SessionLock {
    pub fn acquire(root: &Path) -> Result<Self> {
        let path = root.join(".lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|error| Error::io(&path, error))?;
        let result = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
        if result != 0 {
            return Err(Error::io(&path, std::io::Error::last_os_error()));
        }
        Ok(Self { file })
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        // Closing the description releases the lock; unlocking first just makes
        // the intent explicit.
        unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN) };
    }
}

/// A session id becomes a directory name under the ledger root, so it may not
/// navigate out of it. Without this, `--session ../../elsewhere` made the engine
/// create and write a session outside its own ledger directory.
fn validate_session_id(id: &str) -> Result<()> {
    let rejected = id.is_empty()
        || id == "."
        || id == ".."
        || id.contains('/')
        || id.contains('\\')
        || id.contains('\0');
    if rejected {
        return Err(Error::Invalid(format!(
            "session id must be a single path component: {id:?}"
        )));
    }
    Ok(())
}

pub fn default_ledger_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("WSBOX_HOME") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(dir).join("wsbox");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/share/wsbox");
    }
    PathBuf::from("/tmp/wsbox")
}

impl Session {
    pub fn root_for(ledger_dir: &Path, id: &str) -> PathBuf {
        ledger_dir.join("sessions").join(id)
    }

    pub fn open(params: &SessionOpenParams) -> Result<(Session, SessionOpenResult)> {
        validate_session_id(&params.session)?;
        let capabilities = crate::capabilities::detect();
        let workspace = std::fs::canonicalize(&params.workspace)
            .map_err(|error| Error::io(&params.workspace, error))?;
        if !workspace.is_dir() {
            return Err(Error::Invalid(format!(
                "workspace is not a directory: {}",
                workspace.display()
            )));
        }

        let ledger_dir = params.ledger_dir.clone().unwrap_or_else(default_ledger_dir);
        let root = Self::root_for(&ledger_dir, &params.session);
        if root.exists() {
            return Err(Error::SessionExists(params.session.clone()));
        }

        let (mode, degraded) = resolve_mode(params.mode, &capabilities)?;

        fsutil::ensure_dir(&root)?;
        fsutil::ensure_dir(&root.join("calls"))?;
        fsutil::ensure_dir(&root.join("cas"))?;

        let mut copy_stats = None;
        if mode == Mode::Snapshot {
            let (copied, cloned) = fsutil::copy_tree(&workspace, &root.join("base"))?;
            copy_stats = Some((copied, cloned));
        } else {
            fsutil::ensure_dir(&root.join("upper"))?;
            fsutil::ensure_dir(&root.join("work"))?;
            fsutil::ensure_dir(&root.join("merged"))?;
        }

        let meta = SessionMeta {
            id: params.session.clone(),
            workspace: workspace.clone(),
            mode,
            created_ms: ledger::now_ms(),
            copy_stats,
        };
        fsutil::write_atomic(
            &root.join("session.json"),
            &serde_json::to_vec_pretty(&meta)?,
        )?;

        let index = ChangeIndex::default();
        index.save(&root.join("index.json"))?;

        let cas = Cas::new(root.join("cas"));
        let ledger = Ledger::open(root.join("ledger.jsonl"))?;

        let session = Session {
            meta: meta.clone(),
            root,
            cas,
            index,
            ledger,
        };

        let result = SessionOpenResult {
            session: meta.id.clone(),
            workspace,
            ledger_dir,
            mode,
            capabilities,
            degraded,
        };
        Ok((session, result))
    }

    pub fn load(ledger_dir: &Path, id: &str) -> Result<Session> {
        validate_session_id(id)?;
        let root = Self::root_for(ledger_dir, id);
        if !root.exists() {
            return Err(Error::SessionNotFound(id.to_string()));
        }
        let meta: SessionMeta = serde_json::from_slice(
            &std::fs::read(root.join("session.json")).map_err(|error| Error::io(&root, error))?,
        )?;
        let index = ChangeIndex::load(&root.join("index.json"))?;
        let cas = Cas::new(root.join("cas"));
        let ledger = Ledger::open(root.join("ledger.jsonl"))?;
        Ok(Session {
            meta,
            root,
            cas,
            index,
            ledger,
        })
    }

    pub fn save_index(&self) -> Result<()> {
        self.index.save(&self.root.join("index.json"))
    }

    /// Take the session lock and re-read the state it protects.
    ///
    /// Every mutating operation starts here. Reloading is the point: the caller
    /// loaded this `Session` before the lock existed, so its in-memory index and
    /// ledger position may already be stale.
    fn begin_write(&mut self) -> Result<SessionLock> {
        let guard = SessionLock::acquire(&self.root)?;
        self.index = ChangeIndex::load(&self.root.join("index.json"))?;
        self.ledger = Ledger::open(self.ledger_path())?;
        Ok(guard)
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join("ledger.jsonl")
    }

    /// Digest of the most recent ledger entry — the chain head a client can
    /// pin to prove nothing was rewritten afterwards.
    pub fn ledger_head(&self) -> Result<String> {
        Ok(self.ledger.last_hash().to_string())
    }

    /// Where a given observation strategy keeps the pre-session content of a
    /// path that the session has not touched yet.
    fn baseline_path(&self, key: &str) -> PathBuf {
        match self.meta.mode {
            Mode::Snapshot => self.root.join("base").join(fsutil::key_to_relative(key)),
            // Overlay: the live workspace *is* the baseline for untouched paths.
            _ => self.meta.workspace.join(fsutil::key_to_relative(key)),
        }
    }

    /// Was this path a *directory* in the pre-session baseline?
    ///
    /// Existence is not enough: a file replaced by a directory has to be
    /// reported, and `Path::is_dir` follows symlinks, so a link that happens to
    /// point at a directory would be mistaken for one.
    fn baseline_is_dir(&self, key: &str) -> bool {
        is_real_dir(&self.baseline_path(key))
    }

    fn observe(&self) -> Result<Manifest> {
        match self.meta.mode {
            Mode::Snapshot => fsutil::scan_tree(&self.meta.workspace),
            _ => fsutil::scan_tree(&self.root.join("upper")),
        }
    }

    /// The manifest against which a *single call's* changes are computed.
    ///
    /// In overlay mode this is the upper directory: anything not there is still
    /// the pristine lower layer. In snapshot mode the live tree is compared
    /// against the previous observation, which is why the index matters.
    fn before_manifest(&self) -> Result<Manifest> {
        self.observe()
    }

    pub fn exec(&mut self, params: &ExecParams) -> Result<ExecResult> {
        if params.argv.is_empty() {
            return Err(Error::Invalid("argv must not be empty".into()));
        }
        // One writer at a time: the observation layer is shared, so a second
        // call running concurrently would also see the first one's writes and
        // attribute them to itself.
        let _guard = self.begin_write()?;

        let call_dir = self.root.join("calls").join(sanitize(&params.call));
        fsutil::ensure_dir(&call_dir)?;

        let before = self.before_manifest()?;
        // Make the pre-call content of every observed file durable before the
        // command runs. This is the only moment at which that content still
        // exists, so it cannot be deferred to the diff step.
        self.persist_baseline(&before)?;

        let stdout_path = call_dir.join("stdout.txt");
        let stderr_path = call_dir.join("stderr.txt");

        let overlay = match self.meta.mode {
            Mode::Snapshot => None,
            _ => Some(OverlayDirs {
                lower: self.meta.workspace.clone(),
                upper: self.root.join("upper"),
                work: self.root.join("work"),
                merged: self.root.join("merged"),
            }),
        };

        let request = RunRequest {
            argv: params.argv.clone(),
            cwd: params.cwd.clone(),
            workspace: self.meta.workspace.clone(),
            writable_roots: effective_writable_roots(&params.spec, &self.meta.workspace),
            passthrough: params.spec.passthrough.clone(),
            network: params.spec.network,
            max_open_files: params.spec.max_open_files,
            // Overlay mode always goes through bubblewrap: the merged view has
            // to be bound over the workspace path, which only bubblewrap does.
            sandboxed: params.spec.enabled || overlay.is_some(),
            root_readonly: params.spec.enabled,
            hide_paths: vec![
                self.root
                    .parent()
                    .and_then(Path::parent)
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| self.root.clone()),
            ],
            overlay,
            stdout_path: stdout_path.clone(),
            stderr_path: stderr_path.clone(),
            timeout: params.timeout_ms.map(Duration::from_millis),
        };

        let outcome = crate::sandbox::run(&request)?;

        let after = self.observe()?;
        let (changes, warnings) = self.compute_changes(&before, &after, &params.call)?;
        self.save_index()?;

        let max_output = params.max_output_bytes.unwrap_or(64 * 1024) as usize;
        let (stdout, stdout_bytes, stdout_spill) = read_capped(&stdout_path, max_output, "stdout")?;
        let (stderr, stderr_bytes, stderr_spill) = read_capped(&stderr_path, max_output, "stderr")?;

        let ledger_changes: Vec<LedgerChange> = changes
            .iter()
            .map(|change| LedgerChange {
                path: change.path.clone(),
                op: op_name(change.op).to_string(),
                before_sha: change.before_sha.clone(),
                after_sha: change.after_sha.clone(),
                before_bytes: change.before_bytes,
                after_bytes: change.after_bytes,
                suspicious: change.suspicious,
            })
            .collect();

        let entry = self.ledger.append(LedgerEntry {
            seq: 0,
            at_ms: ledger::now_ms(),
            call: params.call.clone(),
            cwd: params.cwd.display().to_string(),
            argv: params.argv.clone(),
            exit_code: outcome.exit_code,
            timed_out: outcome.timed_out,
            duration_ms: outcome.duration_ms,
            mode: mode_name(self.meta.mode).to_string(),
            changes: ledger_changes,
            passthrough: params
                .spec
                .passthrough
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            prev: String::new(),
            hash: String::new(),
        })?;

        Ok(ExecResult {
            call: params.call.clone(),
            exit_code: outcome.exit_code,
            signal: outcome.signal,
            timed_out: outcome.timed_out,
            duration_ms: outcome.duration_ms,
            changes,
            stdout,
            stderr,
            stdout_bytes,
            stderr_bytes,
            stdout_spill,
            stderr_spill,
            ledger_ref: format!("{}#{}", self.meta.id, entry.seq),
            warnings,
        })
    }

    /// Compute the per-call change set and fold it into the session index.
    fn compute_changes(
        &mut self,
        before: &Manifest,
        after: &Manifest,
        call: &str,
    ) -> Result<(Vec<Change>, Vec<String>)> {
        let mut warnings = Vec::new();
        let mut changes = Vec::new();

        let keys: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
        for key in keys {
            let previous = before.get(key);
            let current = after.get(key);

            // Directories are structural. overlayfs materialises a directory in
            // `upper/` as soon as anything inside it is copied up, and that is
            // not a change the caller asked for — but only when the baseline had
            // a directory there too. A file replaced by a directory is a real
            // change and has to be reported.
            if matches!(current.map(|e| e.kind), Some(Kind::Dir)) && self.baseline_is_dir(key) {
                continue;
            }
            if matches!(previous.map(|e| e.kind), Some(Kind::Dir))
                && matches!(current.map(|e| e.kind), Some(Kind::Dir))
            {
                continue;
            }
            // Fast path: present on both sides with identical content *and*
            // mode. Comparing the mode here matters — a pure `chmod` has the
            // same bytes on both sides, so a content-only comparison would drop
            // it before the state comparison below ever saw it.
            if let (Some(a), Some(b)) = (previous, current)
                && a.mode == b.mode
                && a.same_content(b)
            {
                continue;
            }
            if previous.is_none() && current.is_none() {
                continue;
            }

            let before_state = self.before_state(key, previous)?;
            let after_state = self.after_state(key, current)?;

            // A rewrite that reproduces the previous bytes — including one that
            // copied a file up from the lower layer without changing it — is
            // not a change. Only a mode flip survives this check.
            if before_state.exists == after_state.exists
                && before_state.sha == after_state.sha
                && before_state.mode == after_state.mode
            {
                continue;
            }

            let op = classify(&before_state, &after_state);

            // The baseline is made durable *before* the change is reported, so
            // there is no window in which a diff refers to content that cannot
            // be recovered. A file too large to hold in memory is streamed
            // instead — `apply` and `restore` need the bytes either way.
            if let Some(content) = &before_state.content {
                self.cas.put_bytes(content)?;
            } else if let Some(sha) = &before_state.sha
                && !self.cas.has(sha)
            {
                // The observation layer holds the *after* state by now, so the
                // before bytes can only come from the baseline. Anything that
                // was in the observation layer before the call was already
                // streamed by `persist_baseline`, which is why this usually
                // finds the blob present and does nothing.
                let source = self.baseline_path(key);
                if source.is_file() {
                    self.cas.put_file(&source)?;
                }
            }
            if let Some(content) = &after_state.content {
                self.cas.put_bytes(content)?;
            } else if let Some(sha) = &after_state.sha
                && !self.cas.has(sha)
            {
                let source = self.observation_path(key);
                if source.is_file() {
                    self.cas.put_file(&source)?;
                }
            }

            // `diff::unified` reads a missing side as empty, which is right for
            // an add or a delete and wrong for "we did not read this": a file
            // that grew past the inline limit would render as a whole-file
            // deletion. Render only when every side that has content was
            // actually read.
            let (rendered, truncated) =
                if content_unavailable(&before_state) || content_unavailable(&after_state) {
                    (String::new(), true)
                } else {
                    match diff::unified(
                        before_state.content.as_deref(),
                        after_state.content.as_deref(),
                        key,
                    ) {
                        Some(text) => diff::clamp(&text, MAX_DIFF_BYTES),
                        None => (String::new(), false),
                    }
                };

            let (suspicious, reason) = assess_shrink(&before_state.bytes, &after_state.bytes);

            if content_unavailable(&before_state) || content_unavailable(&after_state) {
                warnings.push(format!(
                    "{key}: content is not available inline (too large or unreadable); \
                     the change is reported without a diff"
                ));
            }

            // Fold into the session index, preserving the first-touch baseline.
            //
            // The entry is kept even when the path is back at its baseline: the
            // baseline blob is what `restore` and the audit surface need, and
            // retention protects it by digest. `is_at_baseline` is what makes
            // the *view* of the change set skip it, so a call that writes the
            // original content back leaves no pending change — the per-call
            // ledger entries still record both events.
            let existing = self.index.entries.get(key).cloned();
            let (baseline_sha, baseline_exists, baseline_mode) = match &existing {
                Some(entry) => (
                    entry.baseline_sha.clone(),
                    entry.baseline_exists,
                    entry.baseline_mode,
                ),
                None => (
                    before_state.sha.clone(),
                    before_state.exists,
                    before_state.mode,
                ),
            };
            let mut ops = existing.as_ref().map(|e| e.ops.clone()).unwrap_or_default();
            ops.push(op);

            // The cumulative change set describes the current state, not every
            // state the path passed through. A call that writes the baseline
            // content back therefore leaves nothing pending; the per-call ledger
            // entries still preserve both events.
            self.index.entries.insert(
                key.clone(),
                IndexEntry {
                    baseline_sha,
                    baseline_exists,
                    baseline_mode,
                    current_sha: after_state.sha.clone(),
                    current_exists: after_state.exists,
                    current_mode: after_state.mode,
                    first_call: existing
                        .as_ref()
                        .map(|e| e.first_call.clone())
                        .unwrap_or_else(|| call.to_string()),
                    last_call: call.to_string(),
                    ops,
                },
            );

            changes.push(Change {
                path: key.clone(),
                op,
                before_bytes: before_state.bytes,
                after_bytes: after_state.bytes,
                before_sha: before_state.sha,
                after_sha: after_state.sha,
                diff: if rendered.is_empty() {
                    None
                } else {
                    Some(rendered)
                },
                diff_truncated: truncated,
                suspicious,
                reason,
                // An addition is reversible by deleting; a directory deletion
                // is reversible by recreating the directory over the lower
                // layer; everything else needs the baseline bytes.
                reversible: before_state.content.is_some()
                    || !before_state.exists
                    || before_state.mode.is_some_and(is_dir_mode),
            });
        }

        changes.sort_by(|a, b| a.path.cmp(&b.path));
        Ok((changes, warnings))
    }

    /// State of `key` immediately before the call.
    ///
    /// `observed` is the entry in the observation layer (the overlay upper
    /// directory, or the live tree in snapshot mode). When it is absent the
    /// path is still at its baseline, which for overlay mode means the real
    /// workspace and for snapshot mode means the session's `base/` copy.
    fn before_state(&self, key: &str, observed: Option<&fsutil::Entry>) -> Result<State> {
        if let Some(entry) = observed {
            if entry.kind == Kind::Whiteout {
                // Deleted by an earlier call in this session.
                return Ok(State::absent());
            }
            let content = match &entry.sha {
                Some(sha) => self.cas.get(sha)?,
                None => None,
            };
            return Ok(State {
                exists: true,
                bytes: Some(entry.size),
                sha: entry.sha.clone(),
                mode: Some(entry.mode),
                content,
            });
        }

        // Not in the observation layer: fall back to the previous recorded
        // state (snapshot mode) or the untouched baseline.
        if self.meta.mode == Mode::Snapshot
            && let Some(indexed) = self.index.entries.get(key)
        {
            let content = match &indexed.current_sha {
                Some(sha) => self.cas.get(sha)?,
                None => None,
            };
            return Ok(State {
                exists: indexed.current_exists,
                bytes: content.as_ref().map(|bytes| bytes.len() as u64),
                sha: indexed.current_sha.clone(),
                mode: indexed.current_mode,
                content,
            });
        }

        let path = self.baseline_path(key);
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            return Ok(State::absent());
        };
        let mode = Some(metadata.mode());
        if metadata.is_dir() {
            return Ok(State {
                exists: true,
                bytes: None,
                sha: None,
                mode,
                content: None,
            });
        }
        match read_layer_content(&path) {
            Ok(Some(content)) => Ok(State {
                exists: true,
                bytes: Some(content.len() as u64),
                sha: Some(fsutil::hash_bytes(&content)),
                mode,
                content: Some(content),
            }),
            // Present, but not read into memory: too large, unreadable, or a
            // kind with no content at all. Hashing streams, so the change is
            // still classified correctly instead of looking like an addition.
            _ if metadata.is_file() || metadata.file_type().is_symlink() => Ok(State {
                exists: true,
                bytes: Some(metadata.len()),
                sha: fsutil::hash_path(&path).ok(),
                mode,
                content: None,
            }),
            _ => Ok(State {
                exists: true,
                bytes: Some(metadata.len()),
                sha: None,
                mode,
                content: None,
            }),
        }
    }

    /// State of `key` immediately after the call.
    ///
    /// The content is read from the observation layer — the CAS does not have
    /// it yet, which is exactly why the caller stores it immediately after.
    fn after_state(&self, key: &str, observed: Option<&fsutil::Entry>) -> Result<State> {
        let Some(entry) = observed else {
            return Ok(State::absent());
        };
        match entry.kind {
            Kind::Whiteout => Ok(State::absent()),
            Kind::File | Kind::Symlink => {
                let path = self.observation_path(key);
                // A file that cannot be read is still a change: report it
                // without a diff rather than failing the whole call.
                match read_layer_content(&path) {
                    Ok(Some(content)) => Ok(State {
                        exists: true,
                        bytes: Some(content.len() as u64),
                        sha: entry
                            .sha
                            .clone()
                            .or_else(|| Some(fsutil::hash_bytes(&content))),
                        mode: Some(entry.mode),
                        content: Some(content),
                    }),
                    Ok(None) | Err(_) => Ok(State {
                        exists: true,
                        bytes: Some(entry.size),
                        sha: entry.sha.clone(),
                        mode: Some(entry.mode),
                        content: None,
                    }),
                }
            }
            _ => Ok(State {
                exists: true,
                bytes: Some(entry.size),
                sha: entry.sha.clone(),
                mode: Some(entry.mode),
                content: None,
            }),
        }
    }

    /// Where the observation layer keeps a path.
    ///
    /// In overlay mode that is the upper directory — the layer that actually
    /// receives writes. In snapshot mode it is the live workspace, which is why
    /// snapshot mode has to snapshot the pre-call content before running.
    fn observation_path(&self, key: &str) -> PathBuf {
        match self.meta.mode {
            Mode::Snapshot => self.meta.workspace.join(fsutil::key_to_relative(key)),
            _ => self.root.join("upper").join(fsutil::key_to_relative(key)),
        }
    }

    /// Copy every regular file in `manifest` into the CAS, skipping anything
    /// already stored.
    ///
    /// This runs *before* the command, because afterwards the content is gone.
    /// The `has` check is what keeps it cheap: in the steady state every digest
    /// is already present, so no file is read twice.
    fn persist_baseline(&self, manifest: &Manifest) -> Result<()> {
        for (key, entry) in manifest {
            let Some(sha) = &entry.sha else {
                continue;
            };
            if self.cas.has(sha) {
                continue;
            }
            let path = self.observation_path(key);
            match entry.kind {
                Kind::File if path.is_file() => {
                    self.cas.put_file(&path)?;
                }
                // A symlink's target is its content, and the link itself is
                // about to be replaced by whatever the command does.
                Kind::Symlink => {
                    if let Ok(target) = fsutil::read_link_bytes(&path) {
                        self.cas.put_bytes(&target)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn changes(&self) -> Result<Vec<Change>> {
        self.changes_filtered(None)
    }

    /// Reconstruct one call's change set from the ledger and the CAS.
    ///
    /// The cumulative view is what `apply` writes, so it is the right input for
    /// a gate on applying. It is the wrong input for judging a *call*, because
    /// one destructive edit makes every later call look destructive too — the
    /// signal never recovers, and a model's per-change discrimination becomes
    /// unmeasurable.
    pub fn changes_for_call(&self, call: &str) -> Result<Vec<Change>> {
        self.changes_filtered(Some(call))
    }

    fn changes_filtered(&self, call: Option<&str>) -> Result<Vec<Change>> {
        if let Some(call) = call {
            let entries = ledger::read_all(&self.ledger_path())?;
            let entry = entries
                .iter()
                .find(|entry| entry.call == call)
                .ok_or_else(|| Error::Invalid(format!("no call `{call}` in this session")))?;
            return entry
                .changes
                .iter()
                .map(|change| self.change_from_ledger(change))
                .collect();
        }

        let mut out = Vec::new();
        for (key, entry) in &self.index.entries {
            if is_at_baseline(entry) {
                continue;
            }
            let before_content = match &entry.baseline_sha {
                Some(sha) => self.cas.get(sha)?,
                None => None,
            };
            let after_content = match &entry.current_sha {
                Some(sha) => self.cas.get(sha)?,
                None => None,
            };
            let (rendered, truncated) =
                match diff::unified(before_content.as_deref(), after_content.as_deref(), key) {
                    Some(text) => diff::clamp(&text, MAX_DIFF_BYTES),
                    None => (String::new(), false),
                };
            let (suspicious, reason) = assess_shrink(
                &before_content.as_ref().map(|b| b.len() as u64),
                &after_content.as_ref().map(|b| b.len() as u64),
            );
            out.push(Change {
                path: key.clone(),
                op: *entry.ops.last().unwrap_or(&Op::Modify),
                before_bytes: before_content.as_ref().map(|b| b.len() as u64),
                after_bytes: after_content.as_ref().map(|b| b.len() as u64),
                before_sha: entry.baseline_sha.clone(),
                after_sha: entry.current_sha.clone(),
                diff: if rendered.is_empty() {
                    None
                } else {
                    Some(rendered)
                },
                diff_truncated: truncated,
                suspicious,
                reason,
                reversible: before_content.is_some() || !entry.baseline_exists,
            });
        }
        Ok(out)
    }

    /// Rebuild one ledger change's diff from the content-addressed store.
    fn change_from_ledger(&self, change: &LedgerChange) -> Result<Change> {
        let before = match &change.before_sha {
            Some(sha) => self.cas.get(sha)?,
            None => None,
        };
        let after = match &change.after_sha {
            Some(sha) => self.cas.get(sha)?,
            None => None,
        };
        let (rendered, truncated) =
            match diff::unified(before.as_deref(), after.as_deref(), &change.path) {
                Some(text) => diff::clamp(&text, MAX_DIFF_BYTES),
                None => (String::new(), false),
            };
        Ok(Change {
            path: change.path.clone(),
            op: parse_op(&change.op),
            before_bytes: change.before_bytes,
            after_bytes: change.after_bytes,
            before_sha: change.before_sha.clone(),
            after_sha: change.after_sha.clone(),
            diff: if rendered.is_empty() {
                None
            } else {
                Some(rendered)
            },
            diff_truncated: truncated,
            suspicious: change.suspicious,
            reason: None,
            reversible: before.is_some() || change.before_sha.is_none(),
        })
    }

    /// Query the audit ledger.
    ///
    /// The ledger is the record of *what happened*; the CAS is the record of
    /// *what the bytes were*. Keeping the two separate is what lets retention
    /// prune content without making the audit trail lie.
    pub fn query_ledger(&self, params: &LedgerQueryParams) -> Result<LedgerQueryResult> {
        let all = ledger::read_all(&self.ledger_path())?;
        let path_filter = match &params.path {
            Some(path) => Some(fsutil::relative_key(path)?),
            None => None,
        };

        let matched: Vec<LedgerEntry> = all
            .iter()
            .filter(|entry| {
                if let Some(call) = &params.call
                    && &entry.call != call
                {
                    return false;
                }
                if let Some(since) = params.since_seq
                    && entry.seq < since
                {
                    return false;
                }
                if let Some(path) = &path_filter
                    && !entry.changes.iter().any(|change| &change.path == path)
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        let total = matched.len() as u64;
        let mut entries = matched;
        if let Some(limit) = params.limit {
            // Newest first: an audit question is almost always "what happened
            // recently", and the tail is what a caller can afford to drop.
            if entries.len() > limit {
                entries.drain(..entries.len() - limit);
            }
        }
        entries.reverse();

        Ok(LedgerQueryResult {
            session: self.meta.id.clone(),
            entries,
            total,
            ledger_entries: all.len() as u64,
            head: self.ledger_head()?,
        })
    }

    /// Every state a path passed through, with availability of each blob.
    ///
    /// Derived from the ledger rather than from a separate version store, so a
    /// pruned blob still appears — flagged `available: false` — instead of the
    /// history silently losing an entry.
    pub fn history(&self, path: &str) -> Result<HistoryResult> {
        let key = fsutil::relative_key(path)?;
        let mut versions = Vec::new();

        for entry in ledger::read_all(&self.ledger_path())? {
            for change in entry.changes.iter().filter(|c| c.path == key) {
                versions.push(Version {
                    seq: entry.seq,
                    call: entry.call.clone(),
                    at_ms: entry.at_ms,
                    op: parse_op(&change.op),
                    before_available: change
                        .before_sha
                        .as_deref()
                        .map(|sha| self.cas.has(sha))
                        .unwrap_or(true),
                    after_available: change
                        .after_sha
                        .as_deref()
                        .map(|sha| self.cas.has(sha))
                        .unwrap_or(true),
                    before_sha: change.before_sha.clone(),
                    before_bytes: change.before_bytes,
                    after_sha: change.after_sha.clone(),
                    after_bytes: change.after_bytes,
                });
            }
        }

        let indexed = self.index.entries.get(&key);
        Ok(HistoryResult {
            session: self.meta.id.clone(),
            path: key,
            baseline_sha: indexed.and_then(|entry| entry.baseline_sha.clone()),
            baseline_available: indexed
                .and_then(|entry| entry.baseline_sha.as_deref())
                .map(|sha| self.cas.has(sha))
                .unwrap_or(true),
            versions,
        })
    }

    /// Prune intermediate content versions.
    ///
    /// Retention is deliberately asymmetric:
    ///
    /// * the **baseline** of every touched path is never evicted — "restore what
    ///   it looked like before the agent started" must always work, and its size
    ///   is bounded by the set of touched files, not by the number of calls;
    /// * the **current** state is never evicted — that is what `apply` writes;
    /// * intermediate versions keep the most recent `keep` per path.
    ///
    /// The ledger is not touched at all. Pruning loses the ability to
    /// re-materialise an old state, never the record that it existed.
    pub fn gc(&mut self, keep: usize, dry_run: bool) -> Result<GcResult> {
        // Pruning reads the index to decide what is protected, and another call
        // could be adding to it right now.
        let _guard = self.begin_write()?;
        let entries = ledger::read_all(&self.ledger_path())?;
        let mut protected: BTreeSet<String> = BTreeSet::new();

        for entry in self.index.entries.values() {
            if let Some(sha) = &entry.baseline_sha {
                protected.insert(sha.clone());
            }
            if let Some(sha) = &entry.current_sha {
                protected.insert(sha.clone());
            }
        }

        // Walk each path's timeline backwards, keeping the newest `keep`
        // distinct digests that are not already protected.
        let mut seen: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for entry in entries.iter().rev() {
            for change in &entry.changes {
                let slots = seen.entry(change.path.clone()).or_default();
                for sha in [change.after_sha.as_ref(), change.before_sha.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    if slots.len() < keep && protected.insert(sha.clone()) {
                        slots.insert(sha.clone());
                    }
                }
            }
        }

        let mut pruned = 0u64;
        let mut pruned_bytes = 0u64;
        let mut affected: BTreeSet<String> = BTreeSet::new();

        for (sha, _path, size) in self.cas.iter()? {
            if protected.contains(&sha) {
                continue;
            }
            if !dry_run {
                self.cas.remove(&sha)?;
            }
            pruned += 1;
            pruned_bytes += size;
            // Attribute the loss back to the paths that referenced it.
            for entry in &entries {
                for change in &entry.changes {
                    if change.before_sha.as_deref() == Some(sha.as_str())
                        || change.after_sha.as_deref() == Some(sha.as_str())
                    {
                        affected.insert(change.path.clone());
                    }
                }
            }
        }

        Ok(GcResult {
            session: self.meta.id.clone(),
            dry_run,
            kept: protected.len() as u64,
            pruned,
            pruned_bytes,
            affected: affected.into_iter().collect(),
        })
    }

    /// Storage and activity summary, including the counterfactual that makes the
    /// retention question concrete: what snapshotting the whole workspace before
    /// every call would have cost.
    pub fn status(&self) -> Result<StatusResult> {
        let entries = ledger::read_all(&self.ledger_path())?;
        let ledger_bytes = std::fs::metadata(self.ledger_path())
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let (cas_blobs, cas_bytes) = self.cas.stats()?;

        let calls = std::fs::read_dir(self.root.join("calls"))
            .map(|dir| dir.count())
            .unwrap_or(0);

        // The honest counterfactual for "just snapshot every time".
        let workspace_bytes: u64 = fsutil::scan_tree(&self.meta.workspace)?
            .values()
            .filter(|entry| entry.kind == Kind::File)
            .map(|entry| entry.size)
            .sum();

        Ok(StatusResult {
            session: self.meta.id.clone(),
            workspace: self.meta.workspace.clone(),
            mode: self.meta.mode,
            changed_paths: self.index.entries.len(),
            ledger_entries: entries.len() as u64,
            ledger_bytes,
            calls,
            cas_blobs,
            cas_bytes,
            workspace_bytes,
            naive_snapshot_bytes: workspace_bytes * calls as u64,
        })
    }

    /// Copy the session's state onto the real workspace.
    ///
    /// In snapshot mode the workspace already holds the changes, so this is a
    /// no-op. In overlay mode every path is verified against its baseline
    /// first: a file the user edited mid-session aborts the whole apply rather
    /// than being silently clobbered.
    pub fn apply(&mut self, force: bool) -> Result<ApplyResult> {
        let _guard = self.begin_write()?;
        if self.meta.mode == Mode::Snapshot {
            return Ok(ApplyResult {
                session: self.meta.id.clone(),
                applied: self
                    .index
                    .entries
                    .iter()
                    .filter(|(_, entry)| !is_at_baseline(entry))
                    .map(|(key, _)| key.clone())
                    .collect(),
                conflicts: Vec::new(),
                ok: true,
            });
        }

        let mut conflicts = Vec::new();
        if !force {
            for (key, entry) in &self.index.entries {
                // A path that is back at its baseline has nothing to write, so
                // it cannot conflict either.
                if is_at_baseline(entry) {
                    continue;
                }
                let path = self.meta.workspace.join(fsutil::key_to_relative(key));
                // Compare content, existence and mode. Hashing only bytes would
                // miss a user `chmod` and then silently overwrite it. `hash_path`
                // also treats a symlink's target as its content rather than
                // hashing whatever the link currently resolves to.
                let expected = (
                    entry.baseline_exists,
                    entry.baseline_sha.clone(),
                    entry.baseline_mode,
                );
                let unchanged = path_identity(&path)
                    .map(|current| current == expected)
                    .unwrap_or(false);
                if !unchanged {
                    conflicts.push(key.clone());
                }
            }
        }
        if !conflicts.is_empty() {
            return Ok(ApplyResult {
                session: self.meta.id.clone(),
                applied: Vec::new(),
                conflicts,
                ok: false,
            });
        }

        let mut applied = Vec::new();
        for (key, entry) in &self.index.entries {
            if is_at_baseline(entry) {
                continue;
            }
            let target = self.meta.workspace.join(fsutil::key_to_relative(key));
            if entry.current_exists {
                let Some(sha) = entry.current_sha.clone() else {
                    // No digest means no content. A directory is reproduced as
                    // a directory; a fifo is reproduced as a fifo; anything
                    // else (a socket, a device node) is a change the engine
                    // reports but cannot write back, and saying so is the only
                    // honest answer — silently skipping it made `apply` claim
                    // success for a change set it did not apply.
                    let source = self.observation_path(key);
                    let mode = entry.current_mode.or_else(|| mode_of(&source));
                    if is_real_dir(&source) {
                        // A baseline file can be replaced by a directory. Remove
                        // the old leaf first; an existing directory is left in
                        // place so applying into it stays incremental.
                        if std::fs::symlink_metadata(&target).is_ok() && !is_real_dir(&target) {
                            fsutil::remove_tree(&target)?;
                        }
                        fsutil::ensure_dir(&target)?;
                        applied.push(key.clone());
                    } else if mode.is_some_and(is_fifo_mode) {
                        create_fifo(&target, mode)?;
                        applied.push(key.clone());
                    } else {
                        return Err(Error::Unsupported(format!(
                            "{key} is not a regular file, directory, symlink or fifo; \
                             it is recorded in the ledger but cannot be applied"
                        )));
                    }
                    continue;
                };
                if !self.materialize(&sha, entry.current_mode, &target)? {
                    return Err(Error::Invalid(format!(
                        "content for {key} ({sha}) is missing from the CAS"
                    )));
                }
            } else {
                fsutil::remove_tree(&target)?;
            }
            applied.push(key.clone());
        }

        Ok(ApplyResult {
            session: self.meta.id.clone(),
            applied,
            conflicts: Vec::new(),
            ok: true,
        })
    }

    /// Put files back to their session baseline. In overlay mode this rewrites
    /// `upper/`; in snapshot mode it rewrites the workspace.
    pub fn restore(&mut self, path: Option<&str>, all: bool) -> Result<Vec<String>> {
        let _guard = self.begin_write()?;
        let mut keys: Vec<String> = if all {
            self.index.entries.keys().cloned().collect()
        } else {
            let key = fsutil::relative_key(
                path.ok_or_else(|| Error::Invalid("restore needs `path` or `all`".into()))?,
            )?;
            vec![key]
        };
        // Restore children before parents. A forward pass removes a directory
        // before its contents and leaves an empty tree behind.
        keys.sort_by(|a, b| path_depth(b).cmp(&path_depth(a)).then_with(|| b.cmp(a)));

        let mut restored = Vec::new();
        for key in keys {
            let Some(entry) = self.index.entries.get(&key).cloned() else {
                continue;
            };
            let target = match self.meta.mode {
                Mode::Snapshot => self.meta.workspace.join(fsutil::key_to_relative(&key)),
                _ => self.root.join("upper").join(fsutil::key_to_relative(&key)),
            };

            if entry.baseline_exists {
                let Some(sha) = entry.baseline_sha.clone() else {
                    // Baseline had no content: a directory. It may have been
                    // replaced by a file or symlink, so clear that leaf first.
                    if std::fs::symlink_metadata(&target).is_ok() && !is_real_dir(&target) {
                        fsutil::remove_tree(&target)?;
                    }
                    let _ = std::fs::create_dir_all(&target);
                    self.index.entries.remove(&key);
                    restored.push(key);
                    continue;
                };
                if !self.materialize(&sha, entry.baseline_mode, &target)? {
                    return Err(Error::Invalid(format!(
                        "baseline for {key} is missing from the CAS"
                    )));
                }
            } else {
                // Children have already been restored/removed, so this is now
                // either a leaf or an empty directory.
                fsutil::remove_tree(&target)?;
            }

            self.index.entries.remove(&key);
            restored.push(key);
        }

        self.save_index()?;
        Ok(restored)
    }

    /// Reproduce one recorded state at `target`, from the CAS.
    ///
    /// `mode` is that state's `st_mode`. It is what tells a symlink from a
    /// regular file and what carries the permission bits, so a mode-only change
    /// is reproducible from the index rather than from whatever the path looks
    /// like now — the difference between `restore` working after `apply` and
    /// only working before it.
    fn materialize(&self, sha: &str, mode: Option<u32>, target: &Path) -> Result<bool> {
        if mode.is_some_and(is_symlink_mode) {
            let Some(target_bytes) = self.cas.get(sha)? else {
                return Ok(false);
            };
            let parent = target.parent().unwrap_or_else(|| Path::new("."));
            fsutil::ensure_dir(parent)?;
            let temp = parent.join(format!(".wsbox-link-{}", std::process::id()));
            let _ = std::fs::remove_file(&temp);
            std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&target_bytes), &temp)
                .map_err(|error| Error::io(&temp, error))?;
            fsutil::remove_tree(target)?;
            std::fs::rename(&temp, target).map_err(|error| Error::io(target, error))?;
            return Ok(true);
        }

        if !self.cas.export(sha, target)? {
            return Ok(false);
        }
        // `export` carries the blob's permissions, which are not the file's:
        // the blob is a CAS artefact, not the workspace entry.
        if let Some(mode) = mode {
            let _ =
                std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode & 0o7777));
        }
        Ok(true)
    }
}

fn resolve_mode(
    requested: Mode,
    capabilities: &crate::protocol::Capabilities,
) -> Result<(Mode, Option<String>)> {
    match requested {
        Mode::Overlay => {
            if capabilities.overlayfs {
                Ok((Mode::Overlay, None))
            } else {
                Err(Error::Unsupported(format!(
                    "overlay mode was requested but is unavailable: {}",
                    capabilities.detail
                )))
            }
        }
        Mode::Snapshot => Ok((Mode::Snapshot, None)),
        Mode::Auto => {
            if capabilities.overlayfs {
                Ok((Mode::Overlay, None))
            } else {
                Ok((
                    Mode::Snapshot,
                    Some(format!(
                        "overlay mode unavailable, degraded to snapshot: {}",
                        capabilities.detail
                    )),
                ))
            }
        }
    }
}

fn effective_writable_roots(spec: &Spec, _workspace: &Path) -> Vec<PathBuf> {
    spec.writable_roots.clone()
}

/// Resolved view of one path on one side of a call.
#[derive(Debug, Clone)]
struct State {
    exists: bool,
    bytes: Option<u64>,
    sha: Option<String>,
    /// Full `st_mode`, so a symlink is distinguishable from a regular file and a
    /// mode-only change is visible even when the bytes are identical.
    mode: Option<u32>,
    content: Option<Vec<u8>>,
}

impl State {
    fn absent() -> Self {
        Self {
            exists: false,
            bytes: None,
            sha: None,
            mode: None,
            content: None,
        }
    }
}

/// Read a path in the baseline/observation layer, treating a symlink's target
/// as its content.
///
/// A symlink is not followed: the journal records what the link *says*, which is
/// what makes retargeting it a change and what makes it reproducible. Anything
/// that is neither a regular file nor a symlink (a fifo, a device, a directory)
/// has no content. A file above [`MAX_INLINE_DIFF_BYTES`] is reported as having
/// no content *for the diff* — its bytes are still hashed and streamed into the
/// CAS elsewhere.
fn read_layer_content(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Ok(Some(fsutil::read_link_bytes(path)?))
        }
        Ok(metadata) if metadata.is_file() => {
            if metadata.len() > MAX_INLINE_DIFF_BYTES {
                return Ok(None);
            }
            Ok(Some(fsutil::read_file(path)?))
        }
        Ok(_) => Ok(None),
        Err(_) => Ok(None),
    }
}

/// True when this state is a file or a symlink whose bytes we do not have in
/// memory. It is the only case where "no diff" means "we did not look" rather
/// than "there is nothing to show" — a directory or a fifo has no content by
/// nature and must not be reported as a clipped diff.
fn content_unavailable(state: &State) -> bool {
    state.exists
        && state.content.is_none()
        && state.mode.is_some_and(|mode| {
            let kind = mode & libc::S_IFMT;
            kind == libc::S_IFREG || kind == libc::S_IFLNK
        })
}

/// True when the path's current state is its baseline state, so nothing is
/// pending: there is nothing for `apply` to write and nothing for the change
/// set to show.
fn is_at_baseline(entry: &IndexEntry) -> bool {
    entry.baseline_exists == entry.current_exists
        && entry.baseline_sha == entry.current_sha
        && entry.baseline_mode == entry.current_mode
}

fn mode_of(path: &Path) -> Option<u32> {
    std::fs::symlink_metadata(path).ok().map(|meta| meta.mode())
}

/// True when the path itself is a directory — a symlink that resolves to one is
/// not, because the change set is about the entry, not what it points at.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

/// Existence, content digest and full mode for conflict detection.
///
/// Unlike `hash_path`, this also represents directories and absence, so
/// replacing a file with a directory (or vice versa) is a conflict rather than
/// an accidental match on `None`.
fn path_identity(path: &Path) -> Result<(bool, Option<String>, Option<u32>)> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let sha = if metadata.file_type().is_symlink() || metadata.is_file() {
                Some(fsutil::hash_path(path)?)
            } else {
                None
            };
            Ok((true, sha, Some(metadata.mode())))
        }
        // `NotADirectory` is the same fact as `NotFound` seen from below: an
        // ancestor is a file, so this path cannot exist. Treating it as an
        // error would report a conflict for every child of a file that the
        // session turned into a directory.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok((false, None, None))
        }
        Err(error) => Err(Error::io(path, error)),
    }
}

fn path_depth(key: &str) -> usize {
    key.split('/')
        .filter(|component| !component.is_empty())
        .count()
}

/// `st_mode` carries the file type in its high bits; a symlink is one of those
/// types, not a file with unusual permissions.
fn is_symlink_mode(mode: u32) -> bool {
    mode & libc::S_IFMT == libc::S_IFLNK
}

fn is_dir_mode(mode: u32) -> bool {
    mode & libc::S_IFMT == libc::S_IFDIR
}

fn is_fifo_mode(mode: u32) -> bool {
    mode & libc::S_IFMT == libc::S_IFIFO
}

/// Create a fifo, replacing whatever is at the path.
///
/// A fifo has no content, so it cannot go through the CAS — but it is a real
/// file a build script may create, and "reported but not applied" is worse than
/// either outcome.
fn create_fifo(target: &Path, mode: Option<u32>) -> Result<()> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    fsutil::ensure_dir(parent)?;
    if std::fs::symlink_metadata(target).is_ok() {
        fsutil::remove_tree(target)?;
    }
    let temp = parent.join(format!(".wsbox-fifo-{}", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    let permissions = mode.unwrap_or(0o644) & 0o7777;
    let path = std::ffi::CString::new(temp.as_os_str().as_bytes())
        .map_err(|_| Error::Invalid(format!("path contains a NUL byte: {}", temp.display())))?;
    if unsafe { libc::mkfifo(path.as_ptr(), permissions) } != 0 {
        return Err(Error::io(&temp, std::io::Error::last_os_error()));
    }
    std::fs::rename(&temp, target).map_err(|error| Error::io(target, error))?;
    Ok(())
}

fn classify(before: &State, after: &State) -> Op {
    match (before.exists, after.exists) {
        (false, true) => Op::Add,
        (true, false) => Op::Delete,
        (true, true) if before.sha == after.sha && same_file_type(before.mode, after.mode) => {
            Op::Chmod
        }
        _ => Op::Modify,
    }
}

/// Compare only the file-type bits of `st_mode`, leaving permissions out.
fn same_file_type(before: Option<u32>, after: Option<u32>) -> bool {
    match (before, after) {
        (Some(before), Some(after)) => before & libc::S_IFMT == after & libc::S_IFMT,
        _ => true,
    }
}

fn assess_shrink(before: &Option<u64>, after: &Option<u64>) -> (bool, Option<String>) {
    let (Some(before), Some(after)) = (before, after) else {
        return (false, None);
    };
    if *before < SUSPICIOUS_MIN_BYTES || *after >= *before {
        return (false, None);
    }
    let removed = 1.0 - (*after as f64 / *before as f64);
    if removed >= SUSPICIOUS_SHRINK_RATIO {
        return (
            true,
            Some(format!(
                "file shrank {:.0}% ({} -> {} bytes)",
                removed * 100.0,
                before,
                after
            )),
        );
    }
    (false, None)
}

fn op_name(op: Op) -> &'static str {
    match op {
        Op::Add => "add",
        Op::Modify => "modify",
        Op::Delete => "delete",
        Op::Chmod => "chmod",
    }
}

/// Inverse of [`op_name`], for reading the ledger back.
fn parse_op(value: &str) -> Op {
    match value {
        "add" => Op::Add,
        "delete" => Op::Delete,
        "chmod" => Op::Chmod,
        _ => Op::Modify,
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Overlay => "overlay",
        Mode::Snapshot => "snapshot",
        Mode::Auto => "auto",
    }
}

/// Read a captured stream, capping what goes back inline and always leaving the
/// full text on disk.
///
/// The `spill` path returned for a truncated stream is the capture file itself
/// (`calls/<id>/stdout.txt`), which is where the command's output was written
/// and where the notice above points. It used to name a `stdout.full.txt` that
/// nothing ever created.
fn read_capped(
    path: &Path,
    max_bytes: usize,
    name: &str,
) -> Result<(String, u64, Option<PathBuf>)> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(Error::io(path, error)),
    };
    let total = bytes.len() as u64;
    if bytes.len() <= max_bytes {
        return Ok((String::from_utf8_lossy(&bytes).to_string(), total, None));
    }

    // Keep both ends: the first line of an error is usually the point, and so
    // is the last.
    let head = max_bytes * 7 / 10;
    let tail = max_bytes - head;
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&bytes[..head]));
    text.push_str(&format!(
        "\n[... {} bytes of {name} omitted; full output at {} ...]\n",
        total as usize - max_bytes,
        path.display()
    ));
    text.push_str(&String::from_utf8_lossy(&bytes[bytes.len() - tail..]));
    Ok((text, total, Some(path.to_path_buf())))
}

/// Keep call ids usable as directory names.
fn sanitize(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "call".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shrink_detection_ignores_small_files() {
        assert_eq!(assess_shrink(&Some(100), &Some(0)), (false, None));
    }

    #[test]
    fn shrink_detection_flags_truncation() {
        let (flag, reason) = assess_shrink(&Some(8192), &Some(0));
        assert!(flag);
        assert!(reason.unwrap().contains("100%"));
    }

    #[test]
    fn shrink_detection_allows_normal_edits() {
        assert_eq!(assess_shrink(&Some(8192), &Some(7000)), (false, None));
    }

    /// One side of a comparison, with the fields these tests care about set.
    fn state(exists: bool, sha: Option<&str>, bytes: Option<u64>, mode: u32) -> State {
        State {
            exists,
            bytes,
            sha: sha.map(str::to_string),
            mode: Some(mode),
            content: None,
        }
    }

    #[test]
    fn additions_are_classified_as_add() {
        let after = state(true, Some("x"), Some(1), 0o100644);
        assert_eq!(classify(&State::absent(), &after), Op::Add);
    }

    #[test]
    fn whiteout_is_classified_as_delete() {
        let before = state(true, Some("x"), Some(10), 0o100644);
        assert_eq!(classify(&before, &State::absent()), Op::Delete);
    }

    /// `classify` sees identical content, which is what a chmod looks like once
    /// the mode comparison upstream has decided it is a real change.
    #[test]
    fn identical_content_is_a_mode_change() {
        let before = state(true, Some("x"), Some(10), 0o100644);
        let after = state(true, Some("x"), Some(10), 0o100755);
        assert_eq!(classify(&before, &after), Op::Chmod);
    }

    #[test]
    fn different_content_is_a_modify() {
        let before = state(true, Some("x"), Some(10), 0o100644);
        let after = state(true, Some("y"), Some(0), 0o100644);
        assert_eq!(classify(&before, &after), Op::Modify);
    }

    #[test]
    fn symlink_mode_is_recognised() {
        assert!(is_symlink_mode(libc::S_IFLNK | 0o777));
        assert!(!is_symlink_mode(libc::S_IFREG | 0o644));
        assert!(is_fifo_mode(libc::S_IFIFO | 0o644));
        assert!(!is_fifo_mode(libc::S_IFREG | 0o644));
    }

    /// A session id is a directory name under the ledger root; anything that
    /// navigates out of it used to create a session outside the ledger.
    #[test]
    fn a_session_id_may_not_escape_the_ledger_directory() {
        assert!(validate_session_id("s1").is_ok());
        assert!(validate_session_id("sess_7f3a").is_ok());
        for bad in ["", ".", "..", "../x", "a/b", "a\\b", "s1\0"] {
            assert!(
                validate_session_id(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_path_at_its_baseline_is_not_pending() {
        let mut entry = IndexEntry {
            baseline_sha: Some("a".into()),
            baseline_exists: true,
            baseline_mode: Some(0o100644),
            current_sha: Some("a".into()),
            current_exists: true,
            current_mode: Some(0o100644),
            first_call: "c1".into(),
            last_call: "c2".into(),
            ops: vec![Op::Modify],
        };
        assert!(is_at_baseline(&entry));

        entry.current_mode = Some(0o100755);
        assert!(!is_at_baseline(&entry), "a mode flip is still pending");
        entry.current_mode = Some(0o100644);
        entry.current_sha = Some("b".into());
        assert!(!is_at_baseline(&entry));
    }
}
