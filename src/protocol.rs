//! Wire protocol.
//!
//! One JSON object per line in each direction (NDJSON). `stdout` carries the
//! protocol only; anything diagnostic goes to `stderr`. A consumer that spawns
//! the engine can therefore treat stdout as a pure channel.
//!
//! Compatibility rules:
//!   * `protocol` is a *major* version. A mismatch is a hard error — the engine
//!     never guesses what an older/newer caller meant.
//!   * Unknown fields are ignored (`serde` default) so minor additions are
//!     forward compatible.
//!   * An unknown `method` returns `unsupported`, never a panic.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

/* ------------------------------- envelope ------------------------------- */

#[derive(Debug, Clone, Deserialize)]
pub struct Envelope {
    #[serde(default)]
    pub protocol: u32,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(default)]
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Response {
    pub protocol: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl Response {
    pub fn ok(result: impl Serialize) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            ok: true,
            result: serde_json::to_value(result).ok(),
            error: None,
            id: None,
        }
    }

    pub fn err(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code: code.into(),
                message: message.into(),
            }),
            id: None,
        }
    }

    pub fn with_id(mut self, id: Option<serde_json::Value>) -> Self {
        self.id = id;
        self
    }
}

/* ------------------------------ capabilities ---------------------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub platform: String,
    pub user_namespace: bool,
    pub overlayfs: bool,
    pub bubblewrap: bool,
    pub landlock_abi: Option<u32>,
    pub seccomp: bool,
    pub fuse: bool,
    pub detail: String,
}

/* ------------------------------ session.open ---------------------------- */

/// How the engine observes workspace writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// overlayfs: the real workspace is never written by the sandbox.
    Overlay,
    /// Copy a baseline once, then diff the live tree against it. Works without
    /// user namespaces; the real workspace *is* written, so this is the weaker
    /// guarantee.
    Snapshot,
    /// Pick the strongest mode the host supports.
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOpenParams {
    pub session: String,
    pub workspace: PathBuf,
    /// Defaults to `$XDG_DATA_HOME/wsbox` (or `~/.local/share/wsbox`).
    #[serde(default)]
    pub ledger_dir: Option<PathBuf>,
    #[serde(default = "default_mode")]
    pub mode: Mode,
    /// Snapshot mode only: how to build the baseline copy.
    #[serde(default)]
    pub copy_mode: CopyMode,
}

fn default_mode() -> Mode {
    Mode::Auto
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyMode {
    /// `FICLONE` where the filesystem supports it, plain copy otherwise.
    #[default]
    Auto,
    /// Always plain copy. Predictable, slow on large trees.
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOpenResult {
    pub session: String,
    pub workspace: PathBuf,
    pub ledger_dir: PathBuf,
    /// Mode that actually took effect, after capability resolution.
    pub mode: Mode,
    pub capabilities: Capabilities,
    /// Non-null when the requested mode could not be honoured. Callers must
    /// decide whether the degradation is acceptable — the engine never
    /// silently downgrades.
    pub degraded: Option<String>,
}

/* --------------------------------- exec --------------------------------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Deny,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Auto,
    Bubblewrap,
    Landlock,
    None,
}

/// Neutral sandbox specification.
///
/// Deliberately free of any agent's tier vocabulary: the engine knows about
/// paths and network, not about `read-only`/`workspace-write`/`approve-all`.
/// Mapping tiers onto this is each agent's job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_backend")]
    pub backend: Backend,
    /// Roots the command may write. Empty means the workspace is read-only.
    #[serde(default)]
    pub writable_roots: Vec<PathBuf>,
    /// Absolute paths inside the workspace that are bound straight from the
    /// real filesystem, bypassing the overlay.
    ///
    /// This is for derived output — `target/`, `node_modules/`, `.venv/` — so a
    /// build writes at native speed and its artefacts do not pollute the diff or
    /// the content store. Writes here are **not journaled and not reversible**,
    /// which is why the list is caller-declared and recorded in the ledger
    /// rather than chosen by the agent.
    #[serde(default)]
    pub passthrough: Vec<PathBuf>,
    #[serde(default = "default_network")]
    pub network: Network,
    #[serde(default)]
    pub max_open_files: Option<u64>,
}

fn default_true() -> bool {
    true
}
fn default_backend() -> Backend {
    Backend::Auto
}
fn default_network() -> Network {
    Network::Deny
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: Backend::Auto,
            writable_roots: Vec::new(),
            passthrough: Vec::new(),
            network: Network::Deny,
            max_open_files: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecParams {
    pub session: String,
    /// Tool-call id. The ledger uses it to attribute changes to a caller.
    pub call: String,
    pub cwd: PathBuf,
    pub argv: Vec<String>,
    #[serde(default)]
    pub spec: Spec,
    #[serde(default)]
    pub ledger_dir: Option<PathBuf>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Cap on captured stdout/stderr returned in the response. Full output is
    /// always spilled to the session directory.
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Add,
    Modify,
    Delete,
    Chmod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub path: String,
    pub op: Op,
    pub before_bytes: Option<u64>,
    pub after_bytes: Option<u64>,
    pub before_sha: Option<String>,
    pub after_sha: Option<String>,
    /// Unified diff. `None` for binary content or when the baseline is
    /// unavailable.
    pub diff: Option<String>,
    pub diff_truncated: bool,
    /// Heuristic: this write removed most of the file. Callers decide what to
    /// do about it; the engine only reports it.
    pub suspicious: bool,
    pub reason: Option<String>,
    pub reversible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResult {
    pub call: String,
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub changes: Vec<Change>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_spill: Option<PathBuf>,
    pub stderr_spill: Option<PathBuf>,
    pub ledger_ref: String,
    /// Set when a change could not be fully captured (e.g. unreadable blob).
    pub warnings: Vec<String>,
}

/* ------------------------------- read side ------------------------------ */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRef {
    pub session: String,
    #[serde(default)]
    pub ledger_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangesResult {
    pub session: String,
    pub changes: Vec<Change>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreParams {
    pub session: String,
    #[serde(default)]
    pub ledger_dir: Option<PathBuf>,
    /// Restore every file to its session baseline.
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyParams {
    pub session: String,
    #[serde(default)]
    pub ledger_dir: Option<PathBuf>,
    /// Apply anyway, overwriting files the user changed during the session.
    /// Without this, a conflict aborts the whole apply.
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyResult {
    pub session: String,
    pub applied: Vec<String>,
    pub conflicts: Vec<String>,
    pub ok: bool,
}

/// Session-scoped bookkeeping of everything the agent has touched.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeIndex {
    pub entries: BTreeMap<String, IndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexEntry {
    /// State of the file in the real workspace when the session first touched
    /// it. `None` means the file did not exist.
    pub baseline_sha: Option<String>,
    pub baseline_exists: bool,
    /// State after the most recent call that touched it.
    pub current_sha: Option<String>,
    pub current_exists: bool,
    pub first_call: String,
    pub last_call: String,
    pub ops: Vec<Op>,
}

impl ChangeIndex {
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(crate::Error::io(path, error)),
        }
    }

    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        crate::fsutil::write_atomic(path, &bytes)
    }
}

/* ------------------------------ audit surface --------------------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerQueryParams {
    pub session: String,
    #[serde(default)]
    pub ledger_dir: Option<PathBuf>,
    /// Only entries attributed to this tool-call id.
    #[serde(default)]
    pub call: Option<String>,
    /// Only entries that touched this workspace-relative path.
    #[serde(default)]
    pub path: Option<String>,
    /// Only entries with `seq >= since_seq`.
    #[serde(default)]
    pub since_seq: Option<u64>,
    /// Newest-first cap on returned entries. `total` still reports the full
    /// match count.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerQueryResult {
    pub session: String,
    pub entries: Vec<crate::ledger::LedgerEntry>,
    /// Entries matching the filter, before `limit` was applied.
    pub total: u64,
    /// Entries in the whole ledger.
    pub ledger_entries: u64,
    pub head: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryParams {
    pub session: String,
    #[serde(default)]
    pub ledger_dir: Option<PathBuf>,
    pub path: String,
}

/// One observed state of a path, derived from the ledger rather than from a
/// separate version store — the ledger is the audit record, the CAS only holds
/// the bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub seq: u64,
    pub call: String,
    pub at_ms: u64,
    pub op: Op,
    pub before_sha: Option<String>,
    pub before_bytes: Option<u64>,
    /// False once retention has evicted the blob. The record of what happened
    /// survives; only the ability to re-materialise it is lost.
    pub before_available: bool,
    pub after_sha: Option<String>,
    pub after_bytes: Option<u64>,
    pub after_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryResult {
    pub session: String,
    pub path: String,
    /// Session-start content. Retention never evicts this.
    pub baseline_sha: Option<String>,
    pub baseline_available: bool,
    pub versions: Vec<Version>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GcParams {
    pub session: String,
    #[serde(default)]
    pub ledger_dir: Option<PathBuf>,
    /// Intermediate versions kept per path, in addition to the baseline and the
    /// current state. `0` keeps only those two.
    #[serde(default = "default_keep")]
    pub keep: usize,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_keep() -> usize {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GcResult {
    pub session: String,
    pub dry_run: bool,
    pub kept: u64,
    pub pruned: u64,
    pub pruned_bytes: u64,
    /// Paths whose history lost versions to this pass.
    pub affected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResult {
    pub session: String,
    pub workspace: PathBuf,
    pub mode: Mode,
    pub changed_paths: usize,
    pub ledger_entries: u64,
    pub ledger_bytes: u64,
    pub calls: usize,
    pub cas_blobs: u64,
    pub cas_bytes: u64,
    /// Total size of the workspace's regular files right now.
    pub workspace_bytes: u64,
    /// `workspaceBytes * calls`: what copying the whole workspace before every
    /// call would have cost. Compare against `casBytes` — and be aware that for
    /// a single large file rewritten with distinct content every time, the CAS
    /// is the more expensive of the two until `gc` runs.
    pub naive_snapshot_bytes: u64,
}
