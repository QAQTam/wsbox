//! Unified diff rendering.
//!
//! The output is the artefact a model actually reads, so it is deliberately
//! git-style and byte-capped: an agent that gets a 4 MB diff learns nothing and
//! burns its context.

use similar::{ChangeTag, TextDiff};

/// Render `before -> after` as a unified diff with `a/`/`b/` headers.
///
/// Returns `None` when either side is not valid UTF-8 (binary content is
/// reported by size and digest instead) or when the text is unchanged.
pub fn unified(before: Option<&[u8]>, after: Option<&[u8]>, path: &str) -> Option<String> {
    let before = decode(before)?;
    let after = decode(after)?;
    if before == after {
        return None;
    }

    let (from_header, to_header) = match (before.is_empty(), after.is_empty()) {
        (true, false) => ("/dev/null".to_string(), format!("b/{path}")),
        (false, true) => (format!("a/{path}"), "/dev/null".to_string()),
        _ => (format!("a/{path}"), format!("b/{path}")),
    };

    let diff = TextDiff::from_lines(before.as_str(), after.as_str());
    let mut out = diff
        .unified_diff()
        .context_radius(3)
        .header(&from_header, &to_header)
        .to_string();

    if out.is_empty() {
        // The text differs only in trailing-newline handling, which the line
        // diff does not render. Say so explicitly rather than emitting nothing.
        out = format!(
            "--- {from_header}\n+++ {to_header}\n@@ trailing newline @@\n-(no newline at end of file)\n+(no newline at end of file)\n"
        );
    }
    Some(out)
}

fn decode(bytes: Option<&[u8]>) -> Option<String> {
    let bytes = bytes.unwrap_or(&[]);
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

/// Truncate a diff to `max_bytes`, keeping the head. Returns the text and
/// whether anything was dropped.
pub fn clamp(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_string(), false);
    }
    let mut cut = max_bytes;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let omitted = text.len() - cut;
    let mut out = String::with_capacity(cut + 64);
    out.push_str(&text[..cut]);
    out.push_str(&format!("\n[... {omitted} bytes of diff omitted ...]\n"));
    (out, true)
}

/// Count added/removed lines in a rendered diff, for summaries.
pub fn stat(diff: &str) -> (usize, usize) {
    let mut added = 0;
    let mut removed = 0;
    for line in diff.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if line.starts_with('+') {
            added += 1;
        } else if line.starts_with('-') {
            removed += 1;
        }
    }
    (added, removed)
}

/// Convenience for tests and callers that want tags rather than text.
pub fn is_binary(before: Option<&[u8]>, after: Option<&[u8]>) -> bool {
    decode(before).is_none() || decode(after).is_none()
}

#[allow(dead_code)]
fn unused_tag_marker() -> ChangeTag {
    ChangeTag::Equal
}
