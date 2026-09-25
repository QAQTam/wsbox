//! Content-addressed store for file contents.
//!
//! Every byte the engine might need to restore is written here *before* the
//! change is reported. That ordering is the whole point: once a diff has been
//! surfaced, the previous content is already durable, so no report can exist
//! for content that cannot be recovered.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::fsutil;

#[derive(Debug, Clone)]
pub struct Cas {
    root: PathBuf,
}

impl Cas {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path_for(&self, sha: &str) -> PathBuf {
        // Two-level fanout keeps large sessions from producing one directory
        // with tens of thousands of entries.
        let (head, tail) = sha.split_at(2.min(sha.len()));
        self.root.join(head).join(tail)
    }

    pub fn has(&self, sha: &str) -> bool {
        self.path_for(sha).exists()
    }

    pub fn put_bytes(&self, bytes: &[u8]) -> Result<String> {
        let sha = fsutil::hash_bytes(bytes);
        let path = self.path_for(&sha);
        if path.exists() {
            return Ok(sha);
        }
        fsutil::write_atomic(&path, bytes)?;
        Ok(sha)
    }

    /// Store a file's contents, returning its digest. The digest is computed by
    /// streaming so large files never sit in memory.
    pub fn put_file(&self, path: &Path) -> Result<String> {
        let sha = fsutil::hash_file(path)?;
        let target = self.path_for(&sha);
        if target.exists() {
            return Ok(sha);
        }
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        fsutil::ensure_dir(parent)?;
        // Copy then rename, so a partially written blob is never visible under
        // its digest.
        let temp = parent.join(format!(".tmp-{}", std::process::id()));
        fs::copy(path, &temp).map_err(|error| Error::io(&temp, error))?;
        fs::rename(&temp, &target).map_err(|error| Error::io(&target, error))?;
        Ok(sha)
    }

    pub fn get(&self, sha: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(sha);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Error::io(path, error)),
        }
    }

    /// Copy a blob out to `target` without loading it into memory.
    pub fn export(&self, sha: &str, target: &Path) -> Result<bool> {
        let source = self.path_for(sha);
        if !source.exists() {
            return Ok(false);
        }
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        fsutil::ensure_dir(parent)?;
        let temp = parent.join(format!(".wsbox-restore-{}", std::process::id()));
        fs::copy(&source, &temp).map_err(|error| Error::io(&temp, error))?;
        fs::rename(&temp, target).map_err(|error| Error::io(target, error))?;
        Ok(true)
    }
}
