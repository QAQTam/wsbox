//! Filesystem primitives: tree scanning, whiteout detection, hashing, atomic
//! writes and copy-on-write copies.
//!
//! The manifest produced by [`scan_tree`] is the unit of comparison for every
//! diff the engine reports. Two details matter for correctness on an overlayfs
//! upper directory:
//!
//!   * a deleted file appears as a **character device with rdev 0:0** (a
//!     whiteout), not as an absent entry — treating it as an ordinary file
//!     would silently turn "deleted" into "empty";
//!   * directories exist in the upper tree as soon as anything inside them is
//!     copied up, so directory-only changes must not be reported as file
//!     changes;
//!   * a symlink's content is its target, so retargeting a link is a content
//!     change rather than an invisible one.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    File,
    Dir,
    Symlink,
    /// overlayfs whiteout: character device 0:0.
    Whiteout,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub kind: Kind,
    pub size: u64,
    pub mtime_ns: i64,
    pub mode: u32,
    /// `None` for directories and anything not read as a regular file.
    pub sha: Option<String>,
}

impl Entry {
    /// Content identity. Two entries with the same identity are reported as
    /// "unchanged" even if mtime moved — rewriting a file with identical bytes
    /// is not a change worth surfacing to a model.
    pub fn same_content(&self, other: &Entry) -> bool {
        self.kind == other.kind && self.sha == other.sha
    }
}

pub type Manifest = BTreeMap<String, Entry>;

/// Walk `root` and record every entry below it, keyed by slash-separated
/// relative path. `root` itself is not included.
pub fn scan_tree(root: &Path) -> Result<Manifest> {
    let mut manifest = Manifest::new();
    if !root.exists() {
        return Ok(manifest);
    }

    for walked in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let walked = walked.map_err(|error| Error::Io {
            path: error
                .path()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| root.to_path_buf()),
            source: error
                .into_io_error()
                .unwrap_or_else(|| std::io::Error::other("walkdir failed")),
        })?;
        let path = walked.path();
        if path == root {
            continue;
        }
        let relative = match path.strip_prefix(root) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        // On Unix, backslash is an ordinary filename byte, and a name may not
        // be valid UTF-8 at all — `encode_key` is what keeps both cases exact.
        let key = encode_key(relative);
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            // A file can vanish between readdir and stat; that is a real
            // outcome, not an error.
            Err(_) => continue,
        };

        let file_type = metadata.file_type();
        let (kind, sha) = if is_whiteout(&metadata) {
            (Kind::Whiteout, None)
        } else if file_type.is_dir() {
            (Kind::Dir, None)
        } else if file_type.is_symlink() {
            // A symlink's content is its target. Hashing it is what makes a
            // retarget a change like any other, instead of invisible because
            // the link's own bytes never move.
            (Kind::Symlink, Some(hash_bytes(&read_link_bytes(path)?)))
        } else if file_type.is_file() {
            (Kind::File, Some(hash_file(path)?))
        } else {
            (Kind::Other, None)
        };

        manifest.insert(
            key,
            Entry {
                kind,
                size: metadata.size(),
                mtime_ns: metadata.mtime_nsec() + metadata.mtime() * 1_000_000_000,
                mode: metadata.mode(),
                sha,
            },
        );
    }

    Ok(manifest)
}

/// overlayfs represents a deletion in the upper layer as a character device
/// with device number 0:0.
pub fn is_whiteout(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_char_device() && metadata.rdev() == 0
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| Error::io(path, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::io(path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Digest of a path's *content*, using the engine's definition of content.
///
/// For a regular file that is its bytes; for a symlink it is the link target,
/// not the bytes the link resolves to. `hash_file` follows links, which is
/// right when the caller already knows it has a file and wrong for anything
/// that compares a path against a recorded digest — a dangling link has no
/// bytes to hash at all, and a link to a file would hash the wrong thing.
pub fn hash_path(path: &Path) -> Result<String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Ok(hash_bytes(&read_link_bytes(path)?))
        }
        Ok(metadata) if metadata.is_file() => hash_file(path),
        Ok(_) => Err(Error::Invalid(format!(
            "{} has no content to hash",
            path.display()
        ))),
        Err(error) => Err(Error::io(path, error)),
    }
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| Error::io(path, error))
}

/// A symlink's target, as raw bytes.
///
/// This is the byte string that [`hash_bytes`] digests for a symlink, and the
/// byte string that is stored in the CAS — so a link is journaled and
/// reproducible exactly like a file, rather than being a path whose content is
/// whatever it currently points at.
pub fn read_link_bytes(path: &Path) -> Result<Vec<u8>> {
    let target = fs::read_link(path).map_err(|error| Error::io(path, error))?;
    Ok(target.as_os_str().as_bytes().to_vec())
}

/// Marker for a path key that is not its own UTF-8 name.
///
/// Unix paths are byte strings, not text: `\xff` is a legal filename and
/// `to_string_lossy` maps it — and every other invalid sequence — onto U+FFFD,
/// which silently merges two distinct files into one key and produces a path
/// that does not exist. So a key is the path's own bytes when they are valid
/// UTF-8, and a hex escape behind this prefix otherwise.
///
/// The encoding is injective because the marker is escaped too: a real file
/// named `!hex:ff` is encoded as `!hex:` + the hex of its own bytes, so it can
/// never be confused with the escaped form of the byte `\xff`.
pub const KEY_ESCAPE: &str = "!hex:";

/// Canonical key for a workspace-relative path.
pub fn encode_key(relative: &Path) -> String {
    let bytes = relative.as_os_str().as_bytes();
    match std::str::from_utf8(bytes) {
        Ok(text) if !text.starts_with(KEY_ESCAPE) => text.to_string(),
        _ => format!("{KEY_ESCAPE}{}", hex(bytes)),
    }
}

/// Inverse of [`encode_key`]: the exact bytes the key stands for.
pub fn decode_key(key: &str) -> Result<Vec<u8>> {
    match key.strip_prefix(KEY_ESCAPE) {
        Some(encoded) => unhex(encoded),
        None => Ok(key.as_bytes().to_vec()),
    }
}

/// Resolve a canonical key to a path relative to `base`.
///
/// Keys come from [`encode_key`] (or from a caller that round-tripped one), so
/// decoding is the only step here; a key that does not decode is treated as a
/// literal name rather than failing, which keeps a hand-written `!hex:...`
/// filename usable.
pub fn key_to_relative(key: &str) -> PathBuf {
    match decode_key(key) {
        Ok(bytes) => PathBuf::from(std::ffi::OsStr::from_bytes(&bytes).to_os_string()),
        Err(_) => PathBuf::from(key),
    }
}

/// Write via a sibling temp file plus `rename(2)`, so a reader never observes a
/// half-written file and a crash never leaves one.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| Error::io(parent, error))?;
    let temp = parent.join(format!(
        ".{}.wsbox-tmp-{}",
        path.file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".into()),
        std::process::id()
    ));
    {
        let mut file = File::create(&temp).map_err(|error| Error::io(&temp, error))?;
        file.write_all(bytes)
            .map_err(|error| Error::io(&temp, error))?;
        file.sync_all().map_err(|error| Error::io(&temp, error))?;
    }
    fs::rename(&temp, path).map_err(|error| Error::io(path, error))?;
    Ok(())
}

/// Recursively copy `from` into `to`, preferring `FICLONE` (reflink) so a
/// baseline snapshot is metadata-only on btrfs/xfs and a real copy elsewhere.
///
/// Returns the number of files copied and the number that fell back to a full
/// copy, which is the honest signal for "how expensive was this snapshot".
pub fn copy_tree(from: &Path, to: &Path) -> Result<(u64, u64)> {
    let mut copied = 0u64;
    let mut cloned = 0u64;
    fs::create_dir_all(to).map_err(|error| Error::io(to, error))?;

    for walked in WalkDir::new(from).follow_links(false).sort_by_file_name() {
        let walked = walked.map_err(|error| Error::Io {
            path: from.to_path_buf(),
            source: error
                .into_io_error()
                .unwrap_or_else(|| std::io::Error::other("walkdir failed")),
        })?;
        let source = walked.path();
        if source == from {
            continue;
        }
        let relative = match source.strip_prefix(from) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        let target = to.join(relative);
        let metadata = match fs::symlink_metadata(source) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            fs::create_dir_all(&target).map_err(|error| Error::io(&target, error))?;
        } else if file_type.is_symlink() {
            let link = fs::read_link(source).map_err(|error| Error::io(source, error))?;
            let _ = fs::remove_file(&target);
            std::os::unix::fs::symlink(&link, &target)
                .map_err(|error| Error::io(&target, error))?;
        } else if file_type.is_file() {
            copied += 1;
            if reflink(source, &target).is_err() {
                fs::copy(source, &target).map_err(|error| Error::io(&target, error))?;
            } else {
                cloned += 1;
            }
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(metadata.mode()));
        }
        // Sockets/fifos/devices are not part of a workspace baseline.
    }

    Ok((copied, cloned))
}

/// `FICLONE` ioctl number from `linux/fs.h`.
const FICLONE: libc::c_ulong = 0x4004_9409;

fn reflink(from: &Path, to: &Path) -> std::io::Result<()> {
    let source = File::open(from)?;
    let target = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(to)?;
    let result = unsafe {
        libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&target),
            FICLONE,
            std::os::fd::AsRawFd::as_raw_fd(&source),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Remove a tree without following symlinks. Used by `discard` and by tests.
pub fn remove_tree(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(path).map_err(|error| Error::io(path, error))
        }
        Ok(_) => fs::remove_file(path).map_err(|error| Error::io(path, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::io(path, error)),
    }
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|error| Error::io(path, error))
}

/// Normalise a caller-supplied path into a canonical workspace-relative key.
///
/// Accepts either a canonical key (what `changes` reports, including the
/// `!hex:` escape) or a plain relative path, and rejects absolute paths and
/// `..` escapes so a change can never be reported — or applied — outside the
/// workspace.
pub fn relative_key(path: &str) -> Result<String> {
    // Already escaped: validate what it decodes to, then pass it through
    // unchanged. A name that merely *looks* like an escape but does not decode
    // falls through and is treated as the literal name it is.
    if let Some(encoded) = path.strip_prefix(KEY_ESCAPE)
        && let Ok(bytes) = unhex(encoded)
    {
        validate_relative(Path::new(std::ffi::OsStr::from_bytes(&bytes)))?;
        return Ok(path.to_string());
    }

    let trimmed = path.trim_start_matches("./").trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(Error::Invalid("empty path".into()));
    }
    let relative = Path::new(trimmed);
    validate_relative(relative)?;
    Ok(encode_key(relative))
}

/// Reject anything that could resolve outside the workspace.
fn validate_relative(relative: &Path) -> Result<()> {
    if relative.is_absolute() {
        return Err(Error::Invalid(format!(
            "absolute path not allowed: {}",
            relative.display()
        )));
    }
    for component in relative.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(Error::Invalid(format!(
                    "path escapes workspace: {}",
                    relative.display()
                )));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(Error::Invalid(format!(
                    "path escapes workspace: {}",
                    relative.display()
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Resolve a workspace-relative key to an absolute path, refusing escapes.
pub fn resolve_in(workspace: &Path, key: &str) -> Result<PathBuf> {
    Ok(workspace.join(key_to_relative(&relative_key(key)?)))
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::Invalid(format!("malformed path key: {text}")));
    }
    let digits = text.as_bytes();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(Error::Invalid(format!(
            "malformed path key: {:?} is not a hex digit",
            other as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_utf8_path_is_its_own_key() {
        assert_eq!(encode_key(Path::new("src/main.rs")), "src/main.rs");
        assert_eq!(decode_key("src/main.rs").unwrap(), b"src/main.rs");
    }

    /// The bug this encoding exists for: `to_string_lossy` maps both of these
    /// onto U+FFFD, so two distinct files became one entry.
    #[test]
    fn non_utf8_paths_get_distinct_keys() {
        let one = encode_key(Path::new(std::ffi::OsStr::from_bytes(b"\xff")));
        let two = encode_key(Path::new(std::ffi::OsStr::from_bytes(b"\xfe")));
        assert_ne!(one, two);
        assert_eq!(one, "!hex:ff");
        assert_eq!(decode_key(&one).unwrap(), b"\xff");
        assert_eq!(decode_key(&two).unwrap(), b"\xfe");
    }

    /// The marker is escaped too, so a real file named `!hex:ff` cannot be
    /// confused with the escaped form of the byte `\xff`.
    #[test]
    fn a_name_that_looks_escaped_is_escaped() {
        let literal = encode_key(Path::new("!hex:ff"));
        assert_ne!(literal, "!hex:ff");
        assert_eq!(decode_key(&literal).unwrap(), b"!hex:ff");
        assert_eq!(
            key_to_relative(&literal),
            PathBuf::from("!hex:ff"),
            "the round trip has to come back to the literal name"
        );
    }

    #[test]
    fn relative_key_round_trips_and_still_rejects_escapes() {
        assert_eq!(relative_key("src/main.rs").unwrap(), "src/main.rs");
        let escaped = relative_key("!hex:ff").unwrap();
        assert_eq!(escaped, "!hex:ff");
        assert!(relative_key("../../etc/passwd").is_err());
        assert!(relative_key("/etc/passwd").is_err());
        // A key that decodes to an escape is rejected, not silently resolved.
        assert!(relative_key("!hex:2e2e2f2e2e2f657463").is_err());
    }

    #[test]
    fn a_utf8_subdirectory_is_not_escaped() {
        assert_eq!(encode_key(Path::new("a/b.txt")), "a/b.txt");
        assert_eq!(key_to_relative("a/b.txt"), PathBuf::from("a/b.txt"));
    }
}
