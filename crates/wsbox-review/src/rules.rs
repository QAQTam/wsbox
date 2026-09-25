//! The deterministic assessor.
//!
//! It runs first, costs nothing, works offline, and answers **exactly** — either
//! `0.0`, `1.0`, or nothing at all. The abstention is the important part. A rules
//! pass that guessed at the middle would be worse than useless: it would look
//! authoritative while being arbitrary, and the router would treat its numbers
//! as facts.
//!
//! So the division of labour is: rules settle the cases where the answer follows
//! from the bytes, and hand everything else to a model. On a well-behaved
//! workload that means most change sets never reach an API at all.

use std::collections::BTreeMap;

use crate::assessor::{Assessor, Result};
use crate::battery;
use crate::question::{Answer, Battery, Calibration, QuestionId};
use crate::state::ChangeSetState;

/// A shrink this large is content loss, not editing.
const LOSS_CERTAIN: f64 = 0.80;
/// Below this, and with nothing deleted, nothing substantive was removed.
const LOSS_IMPLICITLY_NONE: f64 = 0.05;

/// Substrings that make an added line a debugging artefact. Deliberately
/// conservative: a false positive costs one human glance, and only the patterns
/// that are unambiguous are listed.
const DEBUG_MARKERS: &[&str] = &[
    "console.log(",
    "console.debug(",
    "console.warn(",
    "print(",
    "println!(",
    "dbg!(",
    "eprintln!(",
    "System.out.println(",
    "fmt.Println(",
    "printf(",
    "// TODO",
    "// FIXME",
    "// XXX",
    "# TODO",
    "# FIXME",
    "breakpoint()",
    "debugger;",
];

/// Paths whose modification is inherently security-relevant.
const SECURITY_PATH_MARKERS: &[&str] = &[
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "secrets",
    "keystore",
];

pub struct Rules;

impl Assessor for Rules {
    fn id(&self) -> &str {
        "rules"
    }

    fn supports(&self, _battery: &Battery) -> bool {
        true
    }

    fn assess(
        &self,
        state: &ChangeSetState,
        battery: &Battery,
    ) -> Result<BTreeMap<QuestionId, Answer>> {
        let mut answers = BTreeMap::new();
        let facts = &state.precomputed;
        // Questions answered by reading the diff cannot be answered exactly when
        // only part of the diff is available. Saying "0.0, no debug artefacts"
        // about a diff we did not fully see would be a confident lie.
        let diffs_complete = !facts.any_diff_truncated;

        for question in &battery.questions {
            let answer = match question.id.as_str() {
                battery::LOST_CONTENT => {
                    if facts.max_shrink_ratio >= LOSS_CERTAIN {
                        Some(Answer::boolean(1.0, Calibration::Exact))
                    } else if facts.max_shrink_ratio <= LOSS_IMPLICITLY_NONE
                        && facts.files_deleted == 0
                    {
                        Some(Answer::boolean(0.0, Calibration::Exact))
                    } else {
                        None // needs to read the diff
                    }
                }

                battery::REMOVED_BEHAVIOR => {
                    if facts.files_deleted > 0 {
                        // Deleting a file removes whatever it did. That much is
                        // certain; whether it was called is not, so a positive
                        // answer here is conservative on purpose.
                        Some(Answer::boolean(1.0, Calibration::Exact))
                    } else {
                        None
                    }
                }

                battery::TOUCHES_SECURITY => {
                    if state
                        .changes
                        .iter()
                        .any(|change| has_security_marker(&change.path))
                    {
                        Some(Answer::boolean(1.0, Calibration::Exact))
                    } else {
                        // "No security-looking path changed" is not the same as
                        // "no security-relevant change", so this abstains.
                        None
                    }
                }

                battery::LEFTOVER_DEBUG => {
                    if !diffs_complete {
                        None
                    } else {
                        Some(Answer::boolean(
                            if state.changes.iter().any(has_debug_marker) {
                                1.0
                            } else {
                                0.0
                            },
                            Calibration::Exact,
                        ))
                    }
                }

                battery::CATEGORY => {
                    if !diffs_complete {
                        None
                    } else if !state.changes.is_empty()
                        && state
                            .changes
                            .iter()
                            .all(|change| change.diff.as_deref().is_none_or(is_whitespace_only))
                    {
                        Some(Answer::category("formatting", 1.0, Calibration::Exact))
                    } else {
                        None
                    }
                }

                // Severity and "did this go beyond the task" are judgments about
                // intent and consequence. There is nothing exact to say.
                _ => None,
            };

            if let Some(answer) = answer {
                answers.insert(question.id.clone(), answer);
            }
        }

        Ok(answers)
    }
}

fn has_security_marker(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    SECURITY_PATH_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Does this file's diff add a line that is a debugging artefact?
fn has_debug_marker(change: &crate::state::ChangeSummary) -> bool {
    let Some(diff) = &change.diff else {
        return false;
    };
    added_lines(diff).any(|line| {
        let trimmed = line.trim_start();
        DEBUG_MARKERS.iter().any(|marker| trimmed.contains(marker))
    })
}

fn added_lines(diff: &str) -> impl Iterator<Item = &str> {
    diff.lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .map(|line| &line[1..])
}

fn removed_lines(diff: &str) -> impl Iterator<Item = &str> {
    diff.lines()
        .filter(|line| line.starts_with('-') && !line.starts_with("---"))
        .map(|line| &line[1..])
}

/// True when the diff changes only whitespace.
///
/// Compared as multisets of stripped lines, so pure reindentation or a
/// whitespace-only reformat reads as formatting. A diff that is only a trailing
/// newline change also lands here, which is correct.
fn is_whitespace_only(diff: &str) -> bool {
    let mut added: Vec<&str> = added_lines(diff).map(str::trim).collect();
    let mut removed: Vec<&str> = removed_lines(diff).map(str::trim).collect();
    added.sort_unstable();
    removed.sort_unstable();
    added == removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ChangeSetState, ChangeSummary};
    use wsbox::protocol::{Change, Op};

    fn summary(path: &str, diff: Option<&str>) -> ChangeSummary {
        ChangeSummary {
            path: path.into(),
            op: Op::Modify,
            before_bytes: Some(100),
            after_bytes: Some(100),
            diff: diff.map(str::to_string),
        }
    }

    fn state_with(changes: Vec<ChangeSummary>) -> ChangeSetState {
        ChangeSetState {
            task: None,
            changes,
            precomputed: Default::default(),
        }
    }

    fn answer(state: &ChangeSetState, id: &str) -> Option<Answer> {
        Rules
            .assess(state, &battery::change_set())
            .expect("rules")
            .remove(id)
    }

    #[test]
    fn a_large_shrink_is_certain_content_loss() {
        let mut state = state_with(vec![]);
        state.precomputed.max_shrink_ratio = 0.95;
        let answer = answer(&state, battery::LOST_CONTENT).expect("answered");
        assert_eq!(answer.probability, Some(1.0));
        assert_eq!(answer.calibration, Calibration::Exact);
    }

    #[test]
    fn an_ambiguous_shrink_is_left_to_a_model() {
        let mut state = state_with(vec![]);
        state.precomputed.max_shrink_ratio = 0.4;
        assert!(
            answer(&state, battery::LOST_CONTENT).is_none(),
            "the rules pass must abstain rather than guess"
        );
    }

    #[test]
    fn added_print_statements_are_caught_exactly() {
        let state = state_with(vec![summary(
            "src/app.py",
            Some("@@ -1 +1,2 @@\n x = 1\n+print(x)\n"),
        )]);
        let answer = answer(&state, battery::LEFTOVER_DEBUG).expect("answered");
        assert_eq!(answer.probability, Some(1.0));
    }

    #[test]
    fn a_clean_diff_answers_zero_not_abstention() {
        let state = state_with(vec![summary(
            "src/app.py",
            Some("@@ -1 +1 @@\n-old\n+new\n"),
        )]);
        let answer = answer(&state, battery::LEFTOVER_DEBUG).expect("answered");
        assert_eq!(answer.probability, Some(0.0));
    }

    #[test]
    fn whitespace_only_diffs_are_formatting() {
        let state = state_with(vec![summary(
            "src/app.py",
            Some("@@ -1 +1 @@\n-    return 1\n+\treturn 1\n"),
        )]);
        let answer = answer(&state, battery::CATEGORY).expect("answered");
        assert_eq!(answer.category.as_deref(), Some("formatting"));
    }

    #[test]
    fn a_real_change_is_not_called_formatting() {
        let state = state_with(vec![summary(
            "src/app.py",
            Some("@@ -1 +1 @@\n-return 1\n+return 2\n"),
        )]);
        assert!(answer(&state, battery::CATEGORY).is_none());
    }

    #[test]
    fn deleting_a_file_is_certain_behavior_removal() {
        let mut state = state_with(vec![]);
        state.precomputed.files_deleted = 1;
        let answer = answer(&state, battery::REMOVED_BEHAVIOR).expect("answered");
        assert_eq!(answer.probability, Some(1.0));
    }

    #[test]
    fn severity_is_never_answered_by_rules() {
        let state = state_with(vec![]);
        assert!(answer(&state, battery::SEVERITY).is_none());
    }

    #[test]
    fn the_change_type_is_carried_through_from_the_engine() {
        let change = Change {
            path: "a.py".into(),
            op: Op::Delete,
            before_bytes: Some(10),
            after_bytes: None,
            before_sha: None,
            after_sha: None,
            diff: None,
            diff_truncated: false,
            suspicious: false,
            reason: None,
            reversible: true,
        };
        let state = ChangeSetState::from_changes(None, &[change]);
        assert_eq!(state.precomputed.files_deleted, 1);
    }
}
