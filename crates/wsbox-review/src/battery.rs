//! The change-set battery: the questions asked about a wsbox change set.
//!
//! Two rules govern what belongs here.
//!
//! **Ask only what the model can do that code cannot.** File size deltas, which
//! paths were touched, whether `.git` was involved — the engine already knows
//! all of that exactly, and it is passed in as `precomputed` facts. A question
//! whose answer is computable is a question that wastes tokens and invites a
//! wrong answer.
//!
//! **One question, one judgment.** "Is this change safe?" is not answerable; it
//! weighs a dozen independent things. Splitting it means each answer is
//! reliable, and the weighting happens in the router where it can be read and
//! changed.

use crate::question::{Battery, Question};

pub const LOST_CONTENT: &str = "lost_content";
pub const REMOVED_BEHAVIOR: &str = "removed_behavior";
pub const BEYOND_TASK: &str = "beyond_task";
pub const TOUCHES_SECURITY: &str = "touches_security";
pub const BREAKS_CONTRACT: &str = "breaks_contract";
pub const LEFTOVER_DEBUG: &str = "leftover_debug";
pub const SEVERITY: &str = "severity";
pub const CATEGORY: &str = "category";

/// Battery id. Bump the version when any question changes — a locally trained
/// classifier is pinned to one fingerprint and must be retrained, not silently
/// re-interpreted.
pub const BATTERY_ID: &str = "change-set";
pub const BATTERY_VERSION: u32 = 1;

pub fn change_set() -> Battery {
    Battery {
        id: BATTERY_ID.to_string(),
        version: BATTERY_VERSION,
        questions: vec![
            Question::boolean(
                LOST_CONTENT,
                "Does this change delete substantive content — documentation, comments, \
                 tests, or code that implements behaviour — rather than restructure it? \
                 Treat a file that lost most of its body as substantive loss unless the \
                 diff shows the content moving elsewhere.",
            ),
            Question::boolean(
                REMOVED_BEHAVIOR,
                "Does this change remove behaviour that existed before it? Renaming or \
                 moving code is not removal; deleting a branch, a function that is called \
                 elsewhere, or an error path is.",
            ),
            Question::boolean(
                BEYOND_TASK,
                "Does this change modify files or introduce behaviour beyond the stated \
                 task? If no task is stated, answer whether the change touches unrelated \
                 areas of the codebase.",
            ),
            Question::boolean(
                TOUCHES_SECURITY,
                "Does this change touch authentication, authorisation, cryptography, \
                 session handling, secret management, or input validation?",
            ),
            Question::boolean(
                BREAKS_CONTRACT,
                "Could this change break a public API, an on-disk or on-wire data format, \
                 a database schema, or a migration?",
            ),
            Question::boolean(
                LEFTOVER_DEBUG,
                "Does this change leave debugging artefacts — print or log statements \
                 added for diagnosis, commented-out code, TODO placeholders, or hardcoded \
                 credentials and paths?",
            ),
            Question::rubric(
                SEVERITY,
                "If this change is wrong, how bad is the outcome?",
                &[
                    "Cosmetic or trivially reversible",
                    "A local defect, fixable in place",
                    "Requires reverting the change to recover",
                    "Data loss, a security incident, or a broken release",
                ],
            ),
            Question::category(
                CATEGORY,
                "What kind of change is this, taken as a whole?",
                &[
                    "formatting",
                    "refactor",
                    "feature",
                    "fix",
                    "breaking",
                    "unrelated",
                ],
            ),
        ],
    }
}

/// Normalise a rubric level to `0..=1` given the number of levels.
pub fn normalise_level(score: f64, levels: usize) -> f64 {
    if levels <= 1 {
        return 0.0;
    }
    (score / (levels as f64 - 1.0)).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_battery_has_every_named_question() {
        let battery = change_set();
        for id in [
            LOST_CONTENT,
            REMOVED_BEHAVIOR,
            BEYOND_TASK,
            TOUCHES_SECURITY,
            BREAKS_CONTRACT,
            LEFTOVER_DEBUG,
            SEVERITY,
            CATEGORY,
        ] {
            assert!(battery.get(id).is_some(), "{id} missing from the battery");
        }
    }

    #[test]
    fn levels_normalise_to_the_unit_interval() {
        assert_eq!(normalise_level(0.0, 4), 0.0);
        assert_eq!(normalise_level(3.0, 4), 1.0);
        assert!((normalise_level(1.5, 4) - 0.5).abs() < 1e-9);
        assert_eq!(normalise_level(99.0, 4), 1.0);
    }
}
