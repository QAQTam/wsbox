//! The material a review is performed on.
//!
//! `precomputed` is the point of this module. The engine already knows exactly
//! how much each file shrank, which paths were touched, and whether a sensitive
//! path was involved. Passing those as facts means the assessor spends its
//! capacity on semantics — the only thing code cannot do — instead of
//! re-deriving arithmetic it might get wrong.

use serde::{Deserialize, Serialize};

use wsbox::protocol::{Change, Op};

/// A path whose modification should never be waved through by a model.
///
/// These are cheap, deterministic checks. They exist so that a model saying
/// "looks fine" can never be the only thing standing between an agent and a
/// rewritten CI configuration or a deleted lockfile.
const SENSITIVE_PATTERNS: &[&str] = &[
    ".git/",
    ".github/",
    ".gitlab-ci",
    "Jenkinsfile",
    "Dockerfile",
    "docker-compose",
    ".env",
    "id_rsa",
    "credentials",
    "secrets",
    "Cargo.lock",
    "package-lock.json",
    "bun.lock",
    "poetry.lock",
    "go.sum",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeSummary {
    pub path: String,
    pub op: Op,
    pub before_bytes: Option<u64>,
    pub after_bytes: Option<u64>,
    /// Unified diff, already truncated by the engine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrecomputedFacts {
    pub files_changed: usize,
    pub files_deleted: usize,
    pub files_added: usize,
    /// Largest shrink across all modified files, as a fraction of the original.
    pub max_shrink_ratio: f64,
    pub sensitive_paths: Vec<String>,
    pub total_diff_bytes: usize,
    /// True when any diff was clipped, so the assessor knows it is not seeing
    /// everything. A clipped diff should never be auto-approved.
    pub any_diff_truncated: bool,
}

impl PrecomputedFacts {
    pub fn has_sensitive_paths(&self) -> bool {
        !self.sensitive_paths.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeSetState {
    /// The task the agent was given, if the caller knows it. This is what makes
    /// `beyond_task` answerable at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    pub changes: Vec<ChangeSummary>,
    pub precomputed: PrecomputedFacts,
}

impl ChangeSetState {
    pub fn from_changes(task: Option<String>, changes: &[Change]) -> Self {
        let summaries: Vec<ChangeSummary> = changes
            .iter()
            .map(|change| ChangeSummary {
                path: change.path.clone(),
                op: change.op,
                before_bytes: change.before_bytes,
                after_bytes: change.after_bytes,
                diff: change.diff.clone(),
            })
            .collect();

        let mut max_shrink_ratio: f64 = 0.0;
        let mut files_deleted = 0usize;
        let mut files_added = 0usize;
        let mut sensitive_paths = Vec::new();
        let mut total_diff_bytes = 0usize;
        let mut any_diff_truncated = false;

        for (summary, change) in summaries.iter().zip(changes) {
            match summary.op {
                Op::Delete => files_deleted += 1,
                Op::Add => files_added += 1,
                _ => {}
            }
            if let (Some(before), Some(after)) = (summary.before_bytes, summary.after_bytes)
                && before > 0
                && after < before
            {
                max_shrink_ratio = max_shrink_ratio.max(1.0 - after as f64 / before as f64);
            }
            if is_sensitive(&summary.path) {
                sensitive_paths.push(summary.path.clone());
            }
            if let Some(diff) = &summary.diff {
                total_diff_bytes += diff.len();
            }
            any_diff_truncated |= change.diff_truncated;
        }

        Self {
            task,
            changes: summaries,
            precomputed: PrecomputedFacts {
                files_changed: changes.len(),
                files_deleted,
                files_added,
                max_shrink_ratio,
                sensitive_paths,
                total_diff_bytes,
                any_diff_truncated,
            },
        }
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Trim diffs so the state fits a backend's context window.
    ///
    /// Returns whether anything was dropped, and records it in `precomputed` —
    /// because a reviewer that saw only part of a change must not be the reason
    /// a change is auto-applied. The hard rules in the policy key off
    /// `any_diff_truncated`, so trimming here escalates rather than sneaks
    /// through.
    pub fn trim_diffs(&mut self, max_bytes: usize) -> bool {
        let mut used = 0usize;
        let mut trimmed = false;
        for change in &mut self.changes {
            let Some(diff) = change.diff.take() else {
                continue;
            };
            let remaining = max_bytes.saturating_sub(used);
            if diff.len() <= remaining {
                used += diff.len();
                change.diff = Some(diff);
                continue;
            }
            trimmed = true;
            if remaining < 512 {
                // Not enough room for a useful excerpt; omit it entirely.
                change.diff = None;
                continue;
            }
            let mut cut = remaining;
            while cut > 0 && !diff.is_char_boundary(cut) {
                cut -= 1;
            }
            used += cut;
            change.diff = Some(format!(
                "{}\n[... diff truncated by the reviewer at {cut} of {} bytes ...]\n",
                &diff[..cut],
                diff.len()
            ));
        }
        if trimmed {
            self.precomputed.any_diff_truncated = true;
        }
        trimmed
    }
}

/// Deterministic path check. Not a model's job, and not something a model may
/// override.
///
/// Matching is per path component rather than per substring, so `src/secrets.rs`
/// is not mistaken for a credential file and `config/secrets.yaml` is not
/// missed.
pub fn is_sensitive(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let components: Vec<&str> = lower.split('/').filter(|part| !part.is_empty()).collect();

    SENSITIVE_PATTERNS.iter().any(|pattern| {
        let pattern = pattern.to_ascii_lowercase();
        if let Some(directory) = pattern.strip_suffix('/') {
            return components.contains(&directory);
        }
        components.iter().any(|component| {
            *component == pattern
                || component.starts_with(&format!("{pattern}."))
                || component.starts_with(&format!("{pattern}-"))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsbox::protocol::Change;

    fn change(path: &str, op: Op, before: Option<u64>, after: Option<u64>) -> Change {
        Change {
            path: path.into(),
            op,
            before_bytes: before,
            after_bytes: after,
            before_sha: None,
            after_sha: None,
            diff: None,
            diff_truncated: false,
            suspicious: false,
            reason: None,
            reversible: true,
        }
    }

    #[test]
    fn facts_are_computed_from_the_change_set() {
        let changes = vec![
            change("src/app.py", Op::Modify, Some(1000), Some(100)),
            change("gone.txt", Op::Delete, Some(10), None),
            change("new.txt", Op::Add, None, Some(5)),
        ];
        let state = ChangeSetState::from_changes(Some("fix a bug".into()), &changes);

        assert_eq!(state.precomputed.files_changed, 3);
        assert_eq!(state.precomputed.files_deleted, 1);
        assert_eq!(state.precomputed.files_added, 1);
        assert!((state.precomputed.max_shrink_ratio - 0.9).abs() < 1e-9);
    }

    #[test]
    fn sensitive_paths_are_recognised() {
        assert!(is_sensitive(".github/workflows/ci.yml"));
        assert!(is_sensitive("Cargo.lock"));
        assert!(is_sensitive("config/secrets.yaml"));
        assert!(!is_sensitive("src/main.rs"));
    }

    #[test]
    fn sensitive_paths_land_in_the_facts() {
        let changes = vec![change(
            ".github/workflows/ci.yml",
            Op::Modify,
            Some(10),
            Some(20),
        )];
        let state = ChangeSetState::from_changes(None, &changes);
        assert!(state.precomputed.has_sensitive_paths());
    }
}
