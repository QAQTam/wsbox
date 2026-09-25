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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cas::Cas;
use crate::diff;
use crate::error::{Error, Result};
use crate::fsutil::{self, Kind, Manifest};
use crate::ledger::{self, Ledger, LedgerChange, LedgerEntry};
use crate::protocol::{
    ApplyResult, Change, ChangeIndex, ExecParams, ExecResult, IndexEntry, Mode, Op,
    SessionOpenParams, SessionOpenResult, Spec,
};
use crate::sandbox::{OverlayDirs, RunRequest};

/// A file must be at least this large before a shrink is worth flagging.
const SUSPICIOUS_MIN_BYTES: u64 = 1024;
/// ...and must lose this fraction of its content.
const SUSPICIOUS_SHRINK_RATIO: f64 = 0.8;
/// Unified diffs returned inline are capped; the full diff is always on disk.
const MAX_DIFF_BYTES: usize = 64 * 1024;

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
            Mode::Snapshot => self.root.join("base").join(key),
            // Overlay: the live workspace *is* the baseline for untouched paths.
            _ => self.meta.workspace.join(key),
        }
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
        let (stdout, stdout_bytes, stdout_spill) =
            read_capped(&stdout_path, max_output, &call_dir, "stdout")?;
        let (stderr, stderr_bytes, stderr_spill) =
            read_capped(&stderr_path, max_output, &call_dir, "stderr")?;

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

            // Directories are structural: they appear in the upper layer as
            // soon as anything inside them is copied up.
            if matches!(previous.map(|e| e.kind), Some(Kind::Dir))
                && matches!(current.map(|e| e.kind), Some(Kind::Dir))
            {
                continue;
            }
            if let (Some(a), Some(b)) = (previous, current)
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
            if before_state.exists == after_state.exists && before_state.sha == after_state.sha {
                let mode_changed =
                    matches!((previous, current), (Some(a), Some(b)) if a.mode != b.mode);
                if !mode_changed {
                    continue;
                }
            }

            let op = classify(&before_state, &after_state);

            // The baseline is made durable *before* the change is reported, so
            // there is no window in which a diff refers to content that cannot
            // be recovered.
            if let Some(content) = &before_state.content {
                self.cas.put_bytes(content)?;
            }
            if let Some(content) = &after_state.content {
                self.cas.put_bytes(content)?;
            }

            let (rendered, truncated) = match diff::unified(
                before_state.content.as_deref(),
                after_state.content.as_deref(),
                key,
            ) {
                Some(text) => diff::clamp(&text, MAX_DIFF_BYTES),
                None => (String::new(), false),
            };

            let (suspicious, reason) = assess_shrink(&before_state.bytes, &after_state.bytes);

            if before_state.exists && before_state.sha.is_some() && before_state.content.is_none() {
                warnings.push(format!(
                    "baseline content for {key} could not be read; the change is reported without a diff"
                ));
            }

            // Fold into the session index, preserving the first-touch baseline.
            let existing = self.index.entries.get(key).cloned();
            let (baseline_sha, baseline_exists) = match &existing {
                Some(entry) => (entry.baseline_sha.clone(), entry.baseline_exists),
                None => (before_state.sha.clone(), before_state.exists),
            };
            let mut ops = existing.as_ref().map(|e| e.ops.clone()).unwrap_or_default();
            ops.push(op);

            self.index.entries.insert(
                key.clone(),
                IndexEntry {
                    baseline_sha,
                    baseline_exists,
                    current_sha: after_state.sha.clone(),
                    current_exists: after_state.exists,
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
                // An addition is reversible by deleting; everything else needs
                // the baseline bytes.
                reversible: before_state.content.is_some() || !before_state.exists,
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
                content,
            });
        }

        let path = self.baseline_path(key);
        match fsutil::read_file(&path) {
            Ok(content) => Ok(State {
                exists: true,
                bytes: Some(content.len() as u64),
                sha: Some(fsutil::hash_bytes(&content)),
                content: Some(content),
            }),
            Err(_) => Ok(State::absent()),
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
            Kind::File => {
                let path = self.observation_path(key);
                match fsutil::read_file(&path) {
                    Ok(content) => Ok(State {
                        exists: true,
                        bytes: Some(content.len() as u64),
                        sha: entry
                            .sha
                            .clone()
                            .or_else(|| Some(fsutil::hash_bytes(&content))),
                        content: Some(content),
                    }),
                    Err(_) => Ok(State {
                        exists: true,
                        bytes: Some(entry.size),
                        sha: entry.sha.clone(),
                        content: None,
                    }),
                }
            }
            _ => Ok(State {
                exists: true,
                bytes: Some(entry.size),
                sha: entry.sha.clone(),
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
            Mode::Snapshot => self.meta.workspace.join(key),
            _ => self.root.join("upper").join(key),
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
            if entry.kind != Kind::File {
                continue;
            }
            let Some(sha) = &entry.sha else {
                continue;
            };
            if self.cas.has(sha) {
                continue;
            }
            let path = self.observation_path(key);
            if path.is_file() {
                self.cas.put_file(&path)?;
            }
        }
        Ok(())
    }

    pub fn changes(&self) -> Result<Vec<Change>> {
        let mut out = Vec::new();
        for (key, entry) in &self.index.entries {
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

    /// Copy the session's state onto the real workspace.
    ///
    /// In snapshot mode the workspace already holds the changes, so this is a
    /// no-op. In overlay mode every path is verified against its baseline
    /// first: a file the user edited mid-session aborts the whole apply rather
    /// than being silently clobbered.
    pub fn apply(&mut self, force: bool) -> Result<ApplyResult> {
        if self.meta.mode == Mode::Snapshot {
            return Ok(ApplyResult {
                session: self.meta.id.clone(),
                applied: self.index.entries.keys().cloned().collect(),
                conflicts: Vec::new(),
                ok: true,
            });
        }

        let mut conflicts = Vec::new();
        if !force {
            for (key, entry) in &self.index.entries {
                let path = self.meta.workspace.join(key);
                let current = fsutil::hash_file(&path).ok();
                if current != entry.baseline_sha {
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
            let target = self.meta.workspace.join(key);
            if entry.current_exists {
                let sha = entry.current_sha.clone().ok_or_else(|| {
                    Error::Invalid(format!("{key} is marked present but has no digest"))
                })?;
                if !self.cas.export(&sha, &target)? {
                    return Err(Error::Invalid(format!(
                        "content for {key} ({sha}) is missing from the CAS"
                    )));
                }
            } else {
                let _ = std::fs::remove_file(&target);
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
        let keys: Vec<String> = if all {
            self.index.entries.keys().cloned().collect()
        } else {
            let key = fsutil::relative_key(
                path.ok_or_else(|| Error::Invalid("restore needs `path` or `all`".into()))?,
            )?;
            vec![key]
        };

        let mut restored = Vec::new();
        for key in keys {
            let Some(entry) = self.index.entries.get(&key).cloned() else {
                continue;
            };
            let target = match self.meta.mode {
                Mode::Snapshot => self.meta.workspace.join(&key),
                _ => self.root.join("upper").join(&key),
            };

            if entry.baseline_exists {
                let sha = entry
                    .baseline_sha
                    .clone()
                    .ok_or_else(|| Error::Invalid(format!("{key} has no baseline digest")))?;
                if !self.cas.export(&sha, &target)? {
                    return Err(Error::Invalid(format!(
                        "baseline for {key} is missing from the CAS"
                    )));
                }
            } else {
                let _ = std::fs::remove_file(&target);
            }

            self.index.entries.remove(&key);
            restored.push(key);
        }

        self.save_index()?;
        Ok(restored)
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
    content: Option<Vec<u8>>,
}

impl State {
    fn absent() -> Self {
        Self {
            exists: false,
            bytes: None,
            sha: None,
            content: None,
        }
    }
}

fn classify(before: &State, after: &State) -> Op {
    match (before.exists, after.exists) {
        (false, true) => Op::Add,
        (true, false) => Op::Delete,
        (true, true) if before.sha == after.sha => Op::Chmod,
        _ => Op::Modify,
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

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Overlay => "overlay",
        Mode::Snapshot => "snapshot",
        Mode::Auto => "auto",
    }
}

/// Read a captured stream, capping what goes back inline and always leaving the
/// full text on disk.
fn read_capped(
    path: &Path,
    max_bytes: usize,
    call_dir: &Path,
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

    let head = max_bytes * 7 / 10;
    let tail = max_bytes - head;
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&bytes[..head]));
    text.push_str(&format!(
        "\n[... {} bytes omitted; full output at {} ...]\n",
        total as usize - max_bytes,
        path.display()
    ));
    text.push_str(&String::from_utf8_lossy(&bytes[bytes.len() - tail..]));
    let spill = call_dir.join(format!("{name}.full.txt"));
    Ok((text, total, Some(spill)))
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

    #[test]
    fn additions_are_classified_as_add() {
        let after = State {
            exists: true,
            bytes: Some(1),
            sha: Some("x".into()),
            content: None,
        };
        assert_eq!(classify(&State::absent(), &after), Op::Add);
    }

    #[test]
    fn whiteout_is_classified_as_delete() {
        let before = State {
            exists: true,
            bytes: Some(10),
            sha: Some("x".into()),
            content: None,
        };
        assert_eq!(classify(&before, &State::absent()), Op::Delete);
    }

    #[test]
    fn identical_content_is_a_mode_change() {
        let before = State {
            exists: true,
            bytes: Some(10),
            sha: Some("x".into()),
            content: None,
        };
        let after = before.clone();
        assert_eq!(classify(&before, &after), Op::Chmod);
    }

    #[test]
    fn different_content_is_a_modify() {
        let before = State {
            exists: true,
            bytes: Some(10),
            sha: Some("x".into()),
            content: None,
        };
        let after = State {
            exists: true,
            bytes: Some(0),
            sha: Some("y".into()),
            content: None,
        };
        assert_eq!(classify(&before, &after), Op::Modify);
    }
}
