//! Append-only ledger.
//!
//! One JSON object per line, each carrying the digest of the previous line.
//! The chain is what turns "there is a log file" into "the log cannot be edited
//! without it being obvious" — which matters precisely because the thing being
//! logged is an agent that may delete files.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fsutil;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Digest of the empty chain.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerEntry {
    pub seq: u64,
    pub at_ms: u64,
    pub call: String,
    pub cwd: String,
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub mode: String,
    pub changes: Vec<LedgerChange>,
    /// Subtrees bound straight from the real filesystem for this call. Writes
    /// there are neither journaled nor reversible, so the declaration itself is
    /// part of the audit record.
    #[serde(default)]
    pub passthrough: Vec<String>,
    /// Digest of the previous entry (or [`GENESIS`]).
    pub prev: String,
    /// Digest over every other field of this entry plus `prev`.
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerChange {
    pub path: String,
    pub op: String,
    pub before_sha: Option<String>,
    pub after_sha: Option<String>,
    pub before_bytes: Option<u64>,
    pub after_bytes: Option<u64>,
    pub suspicious: bool,
}

#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    last_hash: String,
    next_seq: u64,
}

impl Ledger {
    /// Open (or create) the ledger, resuming the chain from the last entry.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let mut last_hash = GENESIS.to_string();
        let mut next_seq = 0;

        if path.exists() {
            let text = std::fs::read_to_string(&path).map_err(|error| Error::io(&path, error))?;
            for line in text.lines().filter(|line| !line.trim().is_empty()) {
                let entry: LedgerEntry = serde_json::from_str(line)?;
                last_hash = entry.hash;
                next_seq = entry.seq + 1;
            }
        }

        Ok(Self {
            path,
            last_hash,
            next_seq,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Append an entry, computing its position in the chain.
    pub fn append(&mut self, mut entry: LedgerEntry) -> Result<LedgerEntry> {
        entry.seq = self.next_seq;
        entry.prev = self.last_hash.clone();
        entry.hash = digest(&entry)?;

        if let Some(parent) = self.path.parent() {
            fsutil::ensure_dir(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| Error::io(&self.path, error))?;
        let line = serde_json::to_string(&entry)?;
        writeln!(file, "{line}").map_err(|error| Error::io(&self.path, error))?;
        file.flush().map_err(|error| Error::io(&self.path, error))?;

        self.last_hash = entry.hash.clone();
        self.next_seq += 1;
        Ok(entry)
    }
}

/// Digest over the entry's content with `hash` blanked, so verification is a
/// single pass and cannot be circular.
fn digest(entry: &LedgerEntry) -> Result<String> {
    let mut copy = entry.clone();
    copy.hash.clear();
    let canonical = serde_json::to_vec(&copy)?;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Read every entry, in chain order.
///
/// The ledger is the audit record and is never pruned — entries are a few
/// hundred bytes each, so a thousand calls cost a few hundred kilobytes. Only
/// the content store behind it has a retention policy.
pub fn read_all(path: &Path) -> Result<Vec<LedgerEntry>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Error::io(path, error)),
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(Error::Json))
        .collect()
}

/// Verify a ledger file's chain. Returns the number of entries checked.
pub fn verify(path: &Path) -> Result<u64> {
    let text = std::fs::read_to_string(path).map_err(|error| Error::io(path, error))?;
    let mut expected_prev = GENESIS.to_string();
    let mut count = 0u64;

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let entry: LedgerEntry = serde_json::from_str(line)?;
        if entry.prev != expected_prev {
            return Err(Error::Invalid(format!(
                "ledger chain broken at seq {}: prev={} expected={}",
                entry.seq, entry.prev, expected_prev
            )));
        }
        let recomputed = digest(&entry)?;
        if recomputed != entry.hash {
            return Err(Error::Invalid(format!(
                "ledger entry {} has been modified",
                entry.seq
            )));
        }
        expected_prev = entry.hash.clone();
        count += 1;
    }

    Ok(count)
}
