//! `wsbox-review` — the experimental review component.
//!
//! # What this decides, and what it does not
//!
//! This component answers exactly one question: **may this change set be applied
//! to the real workspace without a person looking at it first?**
//!
//! It cannot answer anything else. It never sees a command, it cannot grant a
//! capability, and it has no opinion about whether the sandbox should have let
//! the command run in the first place. That separation is deliberate: the
//! existing permission gate decides *what an agent may do*, and this decides
//! *whether what it did should be kept*. Conflating them would mean an
//! auto-approval could widen a permission boundary, which is exactly the thing
//! it must never be able to do.
//!
//! ```text
//!   permission gate      can this command run?          (unchanged, untouched)
//!   wsbox sandbox        where do writes land?          (unchanged)
//!   wsbox-review         should this change be kept?    <-- this crate
//!   wsbox apply          write it to the workspace      (unchanged)
//! ```
//!
//! # Why it is built around an `Assessor` trait
//!
//! The vendor is the least durable part of the design. A hosted decision model
//! may be replaced by a small local one; either may be unavailable; and a
//! deterministic rules pass should always run first because it is free and
//! exact. So the seam is at the *question* level, not at the API level: a
//! backend answers as much of a versioned battery as it can, and the policy —
//! which is backend-independent — turns the answers into a decision.
//!
//! See `docs/review.md` for the full design.

pub mod assessor;
pub mod battery;
pub mod export;
pub mod policy;
pub mod question;
pub mod rules;
pub mod state;

/// The first hosted backend. Feature-gated so the core carries no network stack
/// and no vendor dependency — the seam is only worth having if the default build
/// does not need the thing behind it.
#[cfg(feature = "jev")]
pub mod jev;

pub use assessor::{Assessor, AssessorError, Chain};
pub use policy::{Action, Decision, Policy};
pub use question::{Answer, Assessment, Battery, Calibration, Question, QuestionKind};
pub use state::{ChangeSetState, PrecomputedFacts};

use question::BackendFailure;

/// Which backends to consult, beyond the always-present rules pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Never call a model. Anything the rules cannot settle goes to a human.
    ///
    /// This is the safe default and the right choice for a first rollout: it
    /// exercises the whole pipeline — battery, chain, router, audit — with the
    /// model slot empty, so the failure paths are the ones that get tested.
    #[default]
    RulesOnly,
    /// Rules first, then a hosted decision model for what the rules left open.
    ///
    /// Any failure — no key, an expired key, a rate limit, a timeout — degrades
    /// to `Review`. It never degrades to an approval.
    Hosted,
}

/// Everything a caller needs to audit a decision after the fact.
#[derive(Debug, Clone)]
pub struct ReviewOutcome {
    pub decision: Decision,
    /// The state as it was actually reviewed, including any diff trimming.
    pub state: ChangeSetState,
    pub battery: Battery,
    pub mode: Mode,
    /// Shadow mode: record the model's verdict, but do not act on it.
    ///
    /// This is the only responsible way to switch a review model on. An
    /// auto-approval that is wrong is invisible — nothing bad happens until
    /// someone notices later. Running in shadow first means the disagreement
    /// between the model and the human is measured *before* anything depends on
    /// it.
    pub shadow: bool,
}

impl ReviewOutcome {
    /// Whether the caller may apply without asking.
    ///
    /// `Decision` can only be constructed by the router, and shadow mode can
    /// only narrow it further — so this is the single gate, and it cannot be
    /// widened from outside.
    pub fn may_auto_apply(&self) -> bool {
        !self.shadow && self.decision.is_auto_apply()
    }

    /// What the model actually said, regardless of shadow mode. This is the
    /// value worth recording and comparing against the human.
    pub fn assessed_action(&self) -> Action {
        self.decision.action()
    }
}

/// Run the whole pipeline: assess, then route.
pub fn review(state: ChangeSetState, mode: Mode, policy: &Policy) -> ReviewOutcome {
    review_with(state, mode, policy, false)
}

/// Run in shadow mode: assess and record, but never permit an auto-apply.
pub fn review_shadow(state: ChangeSetState, mode: Mode, policy: &Policy) -> ReviewOutcome {
    review_with(state, mode, policy, true)
}

fn review_with(state: ChangeSetState, mode: Mode, policy: &Policy, shadow: bool) -> ReviewOutcome {
    let mut assessors: Vec<Box<dyn Assessor>> = vec![Box::new(rules::Rules)];
    let mut prefixed_failures: Vec<BackendFailure> = Vec::new();
    let mut has_model = false;

    if mode == Mode::Hosted {
        match hosted_assessor() {
            Ok(assessor) => {
                assessors.push(assessor);
                has_model = true;
            }
            Err(reason) => {
                // No usable backend. Record why, so the audit record can say
                // "this needed a human because the model was unavailable"
                // rather than leaving it a mystery.
                prefixed_failures.push(BackendFailure {
                    assessor: "hosted".into(),
                    reason,
                });
            }
        }
    }

    review_with_assessors_inner(
        state,
        assessors,
        prefixed_failures,
        has_model,
        policy,
        shadow,
    )
}

/// Run the pipeline against an explicit backend list.
///
/// `review()` with a [`Mode`] covers the built-in backends. This is the seam for
/// anything else — a local model with its own weights, or a test that needs a
/// backend whose behaviour is known. The caller is responsible for the rules
/// pass if it wants one; it is not added implicitly, so the list means exactly
/// what it says.
pub fn review_with_assessors(
    state: ChangeSetState,
    assessors: Vec<Box<dyn Assessor>>,
    policy: &Policy,
    shadow: bool,
) -> ReviewOutcome {
    review_with_assessors_inner(state, assessors, Vec::new(), true, policy, shadow)
}

fn review_with_assessors_inner(
    mut state: ChangeSetState,
    assessors: Vec<Box<dyn Assessor>>,
    prefixed_failures: Vec<BackendFailure>,
    has_model: bool,
    policy: &Policy,
    shadow: bool,
) -> ReviewOutcome {
    let battery = battery::change_set();

    // Only trim for a backend that has a context window to fit. Trimming also
    // sets `any_diff_truncated`, which the hard rules turn into a hold — so the
    // trim can only ever make the outcome stricter.
    if has_model {
        state.trim_diffs(48_000);
    }

    let chain = Chain::new(assessors);
    let mut assessment = chain.assess(&state, &battery);
    assessment.failures.splice(0..0, prefixed_failures);

    let decision = policy::route(&state, &assessment, policy);
    ReviewOutcome {
        decision,
        state,
        battery,
        mode: if has_model {
            Mode::Hosted
        } else {
            Mode::RulesOnly
        },
        shadow,
    }
}

/// Build the hosted backend when the feature is compiled in and a key exists.
#[cfg(feature = "jev")]
fn hosted_assessor() -> Result<Box<dyn Assessor>, String> {
    match jev::Jev::from_env() {
        Ok(jev) => Ok(Box::new(jev)),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(not(feature = "jev"))]
fn hosted_assessor() -> Result<Box<dyn Assessor>, String> {
    Err("this build has no hosted backend (rebuild with --features jev)".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsbox::protocol::{Change, Op};

    fn change(path: &str, before: u64, after: u64) -> Change {
        Change {
            path: path.into(),
            op: Op::Modify,
            before_bytes: Some(before),
            after_bytes: Some(after),
            before_sha: None,
            after_sha: None,
            diff: Some("@@ -1 +1 @@\n-a\n+b\n".into()),
            diff_truncated: false,
            suspicious: false,
            reason: None,
            reversible: true,
        }
    }

    #[test]
    fn rules_only_never_auto_applies_a_real_change() {
        // The rules pass cannot answer `beyond_task` or `severity`, so a change
        // set that is not trivially clean must reach a human.
        let state = ChangeSetState::from_changes(None, &[change("src/app.py", 100, 120)]);
        let outcome = review(state, Mode::RulesOnly, &Policy::default());
        assert!(
            !outcome.may_auto_apply(),
            "rules alone must not approve a change it cannot fully assess"
        );
        assert_eq!(outcome.decision.action(), Action::Review);
    }

    #[test]
    fn rules_only_auto_applies_an_empty_change_set() {
        let state = ChangeSetState::from_changes(None, &[]);
        let outcome = review(state, Mode::RulesOnly, &Policy::default());
        assert!(outcome.may_auto_apply());
    }

    /// A backend that fails must leave its questions unanswered, and the router
    /// must turn that into a human decision.
    ///
    /// Injected rather than simulated by clearing the environment: a unit test
    /// whose result depends on whether `TYPESAFE_API_KEY` happens to be set in
    /// the developer's shell is not a test.
    #[test]
    fn a_failing_backend_falls_back_to_a_human() {
        struct Down;
        impl Assessor for Down {
            fn id(&self) -> &str {
                "down"
            }
            fn supports(&self, _battery: &Battery) -> bool {
                true
            }
            fn assess(
                &self,
                _state: &ChangeSetState,
                _battery: &Battery,
            ) -> std::result::Result<
                std::collections::BTreeMap<question::QuestionId, Answer>,
                AssessorError,
            > {
                Err(AssessorError::Unauthorized("key expired".into()))
            }
        }

        let state = ChangeSetState::from_changes(None, &[change("src/app.py", 100, 120)]);
        let outcome = review_with_assessors(
            state,
            vec![Box::new(rules::Rules), Box::new(Down)],
            &Policy::default(),
            false,
        );

        assert!(!outcome.may_auto_apply());
        assert!(
            outcome
                .decision
                .rationale()
                .fallbacks
                .iter()
                .any(|reason| reason.describe().contains("key expired")),
            "the reason for falling back must be recorded"
        );
    }

    #[test]
    fn the_decision_is_serialisable_for_the_audit_record() {
        let state = ChangeSetState::from_changes(None, &[change("src/app.py", 100, 120)]);
        let outcome = review(state, Mode::RulesOnly, &Policy::default());
        let json = serde_json::to_string(&outcome.decision).expect("serialise");
        assert!(json.contains("\"action\""));
    }

    /// A change set that trips a deterministic rule is held no matter how clean
    /// everything else looks.
    #[test]
    fn a_lockfile_change_is_held() {
        let state = ChangeSetState::from_changes(None, &[change("Cargo.lock", 100, 120)]);
        let outcome = review(state, Mode::RulesOnly, &Policy::default());
        assert_eq!(outcome.decision.action(), Action::Hold);
    }

    /// The whole point of trimming: a change set too large to review in full
    /// must not be auto-applied on the strength of the part that fit.
    #[test]
    fn trimming_a_diff_escalates() {
        let big_diff = format!("@@ -1 +1 @@\n{}\n", "+x".repeat(60_000));
        let mut change = change("src/app.py", 100, 120);
        change.diff = Some(big_diff);
        let state = ChangeSetState::from_changes(None, &[change]);

        let mut trimmed = state.clone();
        assert!(trimmed.trim_diffs(48_000));
        assert!(trimmed.precomputed.any_diff_truncated);

        let outcome = review(trimmed, Mode::RulesOnly, &Policy::default());
        assert!(!outcome.may_auto_apply());
    }
}
