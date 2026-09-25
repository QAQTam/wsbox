//! Policy: turning an assessment into a decision.
//!
//! This module is the part that must not change when the backend does. Swapping
//! a hosted decision model for a local classifier changes which answers arrive,
//! not what a threshold means — provided the answers are calibrated, which is
//! what [`Calibration`] tracks.
//!
//! Two invariants hold here, and both are fail-closed:
//!
//! 1. **A missing answer is a reason to ask a human, never a reason to guess.**
//!    If the battery asked something the assessors could not answer, no
//!    auto-approval is possible.
//! 2. **`AutoApply` can only be produced by [`route`].** The variant lives in a
//!    private enum, so no caller — however well-intentioned — can construct one.
//!    A backend that is down, a key that expired, a model that is unsure: all of
//!    them land on `Review` by construction rather than by remembering to check.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::battery;
use crate::question::{Answer, Assessment, QuestionId};
use crate::state::ChangeSetState;

/// What happens when a hazard fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HazardAction {
    /// Stop and wait for a person.
    Hold,
    /// Flag it, but do not block on its own.
    Review,
}

/// Deterministic rules that a model may never override.
///
/// These exist because a model is a judgment layer, not a boundary. A model
/// saying "looks fine" must never be the only thing standing between an agent
/// and a rewritten CI configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardRules {
    /// Any change to a path the engine flagged as sensitive requires a person.
    pub hold_sensitive_paths: bool,
    /// A clipped diff means the reviewer is not seeing everything.
    pub hold_truncated_diffs: bool,
    /// Shrink above this ratio requires a person, whatever the model says.
    pub hold_shrink_above: f64,
    /// Change sets larger than this are not eligible for auto-approval.
    pub max_files_for_auto: usize,
}

impl Default for HardRules {
    fn default() -> Self {
        Self {
            hold_sensitive_paths: true,
            hold_truncated_diffs: true,
            hold_shrink_above: 0.50,
            max_files_for_auto: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub hard: HardRules,
    /// Probability at or above which a hazard performs its configured action.
    pub action_threshold: f64,
    /// Probability at or above which a hazard is at least worth a look. Also
    /// the lower edge of the "the model is not sure" band for boolean answers,
    /// which is the only uncertainty signal those carry.
    pub review_threshold: f64,
    /// Below this, the assessor is saying it cannot decide. Applies to answers
    /// that carry a confidence at all.
    pub min_confidence: f64,
    /// Severity (normalised to `0..=1`) at or above which a review escalates.
    pub severity_escalate: f64,
    pub hazards: BTreeMap<QuestionId, HazardAction>,
}

impl Default for Policy {
    fn default() -> Self {
        let hazards = BTreeMap::from([
            (battery::LOST_CONTENT.to_string(), HazardAction::Hold),
            (battery::REMOVED_BEHAVIOR.to_string(), HazardAction::Hold),
            (battery::BREAKS_CONTRACT.to_string(), HazardAction::Hold),
            (battery::TOUCHES_SECURITY.to_string(), HazardAction::Review),
            (battery::BEYOND_TASK.to_string(), HazardAction::Review),
            (battery::LEFTOVER_DEBUG.to_string(), HazardAction::Review),
        ]);

        Self {
            hard: HardRules::default(),
            // Deliberately conservative. These are starting points to be tuned
            // against your own labelled change sets, not settled values.
            action_threshold: 0.70,
            review_threshold: 0.35,
            min_confidence: 0.50,
            severity_escalate: 0.66,
            hazards,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiredHazard {
    pub question: QuestionId,
    pub probability: f64,
    pub action: HazardAction,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FallbackReason {
    /// The battery asked something no assessor could answer.
    Unanswered { question: QuestionId },
    /// The answer exists but its numbers are not calibrated, so no threshold on
    /// them would mean anything.
    Uncalibrated { question: QuestionId },
    /// The assessor answered, but told us it is not sure.
    LowConfidence { confidence: f64 },
    /// An assessor was tried and failed — an expired key, a network error, a
    /// stale local model.
    BackendFailed { assessor: String, reason: String },
}

impl FallbackReason {
    pub fn describe(&self) -> String {
        match self {
            Self::Unanswered { question } => format!("`{question}` was not evaluated"),
            Self::Uncalibrated { question } => {
                format!("`{question}` came back uncalibrated, so thresholds do not apply")
            }
            Self::LowConfidence { confidence } => {
                format!("assessor confidence {confidence:.2} is below the floor")
            }
            Self::BackendFailed { assessor, reason } => {
                format!("assessor `{assessor}` failed: {reason}")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rationale {
    pub summary: String,
    pub assessor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub fired: Vec<FiredHazard>,
    pub hard_rules: Vec<String>,
    pub fallbacks: Vec<FallbackReason>,
    /// Every answer, so the audit record shows what the decision was made on.
    pub answers: BTreeMap<QuestionId, Answer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    AutoApply,
    Review,
    Hold,
}

/// The outcome of a review.
///
/// The inner enum is private: a `Decision` can only be built by [`route`]. That
/// is what makes "fail closed" a property of the type rather than a rule someone
/// has to remember.
#[derive(Debug, Clone, Serialize)]
pub struct Decision(Inner);

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Inner {
    AutoApply { rationale: Rationale },
    Review { rationale: Rationale },
    Hold { rationale: Rationale },
}

impl Decision {
    fn auto_apply(rationale: Rationale) -> Self {
        Self(Inner::AutoApply { rationale })
    }
    fn review(rationale: Rationale) -> Self {
        Self(Inner::Review { rationale })
    }
    fn hold(rationale: Rationale) -> Self {
        Self(Inner::Hold { rationale })
    }

    pub fn action(&self) -> Action {
        match &self.0 {
            Inner::AutoApply { .. } => Action::AutoApply,
            Inner::Review { .. } => Action::Review,
            Inner::Hold { .. } => Action::Hold,
        }
    }

    pub fn rationale(&self) -> &Rationale {
        match &self.0 {
            Inner::AutoApply { rationale }
            | Inner::Review { rationale }
            | Inner::Hold { rationale } => rationale,
        }
    }

    pub fn is_auto_apply(&self) -> bool {
        self.action() == Action::AutoApply
    }

    /// One-line explanation, suitable for a tool result or a log.
    pub fn explain(&self) -> String {
        let rationale = self.rationale();
        let mut text = rationale.summary.clone();
        for fallback in &rationale.fallbacks {
            text.push_str("\n  - ");
            text.push_str(&fallback.describe());
        }
        for rule in &rationale.hard_rules {
            text.push_str("\n  - hard rule: ");
            text.push_str(rule);
        }
        for fired in &rationale.fired {
            text.push_str(&format!(
                "\n  - {} = {:.2} -> {:?}",
                fired.question, fired.probability, fired.action
            ));
        }
        text
    }
}

/// Turn an assessment into a decision.
///
/// Order matters. Hard rules are checked first and can only make the outcome
/// stricter; the model can never loosen them.
pub fn route(state: &ChangeSetState, assessment: &Assessment, policy: &Policy) -> Decision {
    let mut hard_rules = Vec::new();
    let mut fallbacks: Vec<FallbackReason> = assessment
        .failures
        .iter()
        .map(|failure| FallbackReason::BackendFailed {
            assessor: failure.assessor.clone(),
            reason: failure.reason.clone(),
        })
        .collect();

    // 1. Deterministic hard rules. These bypass the model entirely.
    let facts = &state.precomputed;
    if policy.hard.hold_sensitive_paths && facts.has_sensitive_paths() {
        hard_rules.push(format!(
            "sensitive paths touched: {}",
            facts.sensitive_paths.join(", ")
        ));
    }
    if policy.hard.hold_truncated_diffs && facts.any_diff_truncated {
        hard_rules.push("a diff was truncated, so the reviewer saw only part of it".into());
    }
    if facts.max_shrink_ratio > policy.hard.hold_shrink_above {
        hard_rules.push(format!(
            "largest shrink {:.0}% exceeds the hard limit {:.0}%",
            facts.max_shrink_ratio * 100.0,
            policy.hard.hold_shrink_above * 100.0
        ));
    }
    if facts.files_changed > policy.hard.max_files_for_auto {
        hard_rules.push(format!(
            "{} files changed, above the auto-apply limit of {}",
            facts.files_changed, policy.hard.max_files_for_auto
        ));
    }

    // 2. An empty change set needs no review at all.
    if state.is_empty() && hard_rules.is_empty() {
        return Decision::auto_apply(Rationale {
            summary: "nothing changed".into(),
            assessor: assessment.assessor.clone(),
            model: assessment.model.clone(),
            fired: Vec::new(),
            hard_rules,
            fallbacks,
            answers: assessment.answers.clone(),
        });
    }

    // 3. Hazards.
    let mut fired = Vec::new();
    for (question, action) in &policy.hazards {
        let Some(answer) = assessment.answer(question) else {
            fallbacks.push(FallbackReason::Unanswered {
                question: question.clone(),
            });
            continue;
        };
        if !answer.calibration.is_trustworthy() {
            fallbacks.push(FallbackReason::Uncalibrated {
                question: question.clone(),
            });
            continue;
        }
        let Some(probability) = answer.probability else {
            // A category or rubric answer where a boolean was expected. Treat it
            // as an answer we do not have.
            fallbacks.push(FallbackReason::Unanswered {
                question: question.clone(),
            });
            continue;
        };

        if probability >= policy.action_threshold {
            fired.push(FiredHazard {
                question: question.clone(),
                probability,
                action: *action,
            });
        } else if probability >= policy.review_threshold {
            fired.push(FiredHazard {
                question: question.clone(),
                probability,
                action: HazardAction::Review,
            });
        }
    }

    // 4. Confidence floor. Only answers that carry a confidence can be judged;
    //    boolean answers express uncertainty through the probability band above.
    for (question, answer) in &assessment.answers {
        if let Some(confidence) = answer.confidence
            && confidence < policy.min_confidence
        {
            fallbacks.push(FallbackReason::LowConfidence { confidence });
            let _ = question;
        }
    }

    // 5. Severity amplifies everything: a high-severity change turns a review
    //    into a hold, and a high-severity change that fired nothing still gets a
    //    look.
    let severity = assessment
        .answer(battery::SEVERITY)
        .filter(|answer| answer.calibration.is_trustworthy())
        .and_then(|answer| answer.level);

    let severe = severity.is_some_and(|level| level >= policy.severity_escalate);
    if severe {
        for hazard in &mut fired {
            if hazard.action == HazardAction::Review {
                hazard.action = HazardAction::Hold;
            }
        }
    }

    // 6. Precedence. Hold beats Review beats AutoApply.
    let mut actions: Vec<Action> = Vec::new();
    if !hard_rules.is_empty() {
        actions.push(Action::Hold);
    }
    if !fallbacks.is_empty() {
        actions.push(Action::Review);
    }
    for hazard in &fired {
        actions.push(match hazard.action {
            HazardAction::Hold => Action::Hold,
            HazardAction::Review => Action::Review,
        });
    }
    if severe && actions.is_empty() {
        actions.push(Action::Review);
    }

    let summary = summarise(&actions, &hard_rules, &fallbacks, &fired);
    let rationale = Rationale {
        summary,
        assessor: assessment.assessor.clone(),
        model: assessment.model.clone(),
        fired,
        hard_rules,
        fallbacks,
        answers: assessment.answers.clone(),
    };

    if actions.contains(&Action::Hold) {
        Decision::hold(rationale)
    } else if actions.contains(&Action::Review) {
        Decision::review(rationale)
    } else {
        Decision::auto_apply(rationale)
    }
}

fn summarise(
    actions: &[Action],
    hard_rules: &[String],
    fallbacks: &[FallbackReason],
    fired: &[FiredHazard],
) -> String {
    if actions.contains(&Action::Hold) {
        if !hard_rules.is_empty() {
            return "held: a deterministic rule requires a person".into();
        }
        if let Some(worst) = fired
            .iter()
            .filter(|hazard| hazard.action == HazardAction::Hold)
            .max_by(|a, b| a.probability.total_cmp(&b.probability))
        {
            return format!("held: `{}` at {:.2}", worst.question, worst.probability);
        }
        return "held".into();
    }
    if actions.contains(&Action::Review) {
        if !fallbacks.is_empty() {
            return format!("needs review: {}", fallbacks[0].describe());
        }
        if let Some(any) = fired.first() {
            return format!("needs review: `{}` at {:.2}", any.question, any.probability);
        }
        return "needs review".into();
    }
    "auto-approved: every question was answered and none fired".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::question::{Answer, Calibration};

    fn state() -> ChangeSetState {
        // One ordinary change, so the "empty change set needs no review"
        // short-circuit does not mask the behaviour under test.
        let mut state = ChangeSetState::from_changes(Some("fix a bug".into()), &[]);
        state.changes.push(crate::state::ChangeSummary {
            path: "src/app.py".into(),
            op: wsbox::protocol::Op::Modify,
            before_bytes: Some(100),
            after_bytes: Some(120),
            diff: Some("@@ -1 +1 @@\n-a\n+b\n".into()),
        });
        state.precomputed.files_changed = 1;
        state
    }

    /// An assessment in which every hazard is answered at `0.0`, so only the
    /// thing under test can move the outcome.
    fn quiet() -> Assessment {
        let mut assessment = Assessment::empty("test");
        for id in Policy::default().hazards.keys() {
            assessment.answers.insert(
                id.clone(),
                Answer::boolean(
                    0.0,
                    Calibration::Calibrated {
                        source: "test".into(),
                    },
                ),
            );
        }
        assessment.answers.insert(
            battery::SEVERITY.to_string(),
            Answer::level(
                0.0,
                0.9,
                Calibration::Calibrated {
                    source: "test".into(),
                },
            ),
        );
        assessment
    }

    #[test]
    fn a_clean_assessment_auto_applies() {
        let decision = route(&state(), &quiet(), &Policy::default());
        assert_eq!(decision.action(), Action::AutoApply);
    }

    /// The central invariant: no answer, no auto-approval.
    #[test]
    fn a_missing_answer_blocks_auto_approval() {
        let mut assessment = quiet();
        assessment.answers.remove(battery::LOST_CONTENT);

        let decision = route(&state(), &assessment, &Policy::default());
        assert_ne!(decision.action(), Action::AutoApply);
        assert!(
            decision
                .rationale()
                .fallbacks
                .iter()
                .any(|f| matches!(f, FallbackReason::Unanswered { .. }))
        );
    }

    /// An expired API key is the case the user cares about: it must degrade to a
    /// human, never to an approval.
    #[test]
    fn an_expired_api_key_falls_back_to_a_human() {
        let mut assessment = quiet();
        assessment.answers.clear();
        assessment.failures.push(crate::question::BackendFailure {
            assessor: "jev".into(),
            reason: "authentication rejected: key expired".into(),
        });

        let decision = route(&state(), &assessment, &Policy::default());
        assert_eq!(decision.action(), Action::Review);
        assert!(decision.explain().contains("key expired"));
    }

    #[test]
    fn an_uncalibrated_answer_is_not_thresholded() {
        let mut assessment = quiet();
        assessment.answers.insert(
            battery::LOST_CONTENT.to_string(),
            Answer::boolean(0.0, Calibration::Uncalibrated),
        );

        let decision = route(&state(), &assessment, &Policy::default());
        assert_ne!(
            decision.action(),
            Action::AutoApply,
            "an uncalibrated 0.0 is not evidence of safety"
        );
    }

    #[test]
    fn a_fired_hazard_holds() {
        let mut assessment = quiet();
        assessment.answers.insert(
            battery::LOST_CONTENT.to_string(),
            Answer::boolean(0.9, Calibration::Calibrated { source: "t".into() }),
        );
        assert_eq!(
            route(&state(), &assessment, &Policy::default()).action(),
            Action::Hold
        );
    }

    #[test]
    fn the_uncertain_band_reviews_rather_than_holds() {
        let mut assessment = quiet();
        assessment.answers.insert(
            battery::LOST_CONTENT.to_string(),
            Answer::boolean(0.5, Calibration::Calibrated { source: "t".into() }),
        );
        assert_eq!(
            route(&state(), &assessment, &Policy::default()).action(),
            Action::Review
        );
    }

    #[test]
    fn low_confidence_reviews() {
        let mut assessment = quiet();
        assessment.answers.insert(
            battery::SEVERITY.to_string(),
            Answer::level(0.0, 0.2, Calibration::Calibrated { source: "t".into() }),
        );
        assert_eq!(
            route(&state(), &assessment, &Policy::default()).action(),
            Action::Review
        );
    }

    #[test]
    fn a_sensitive_path_holds_regardless_of_the_model() {
        let mut state = state();
        state.precomputed.sensitive_paths = vec![".github/workflows/ci.yml".into()];

        let decision = route(&state, &quiet(), &Policy::default());
        assert_eq!(
            decision.action(),
            Action::Hold,
            "a model must never be able to wave through a CI config change"
        );
    }

    #[test]
    fn a_truncated_diff_holds() {
        let mut state = state();
        state.precomputed.any_diff_truncated = true;
        assert_eq!(
            route(&state, &quiet(), &Policy::default()).action(),
            Action::Hold
        );
    }

    #[test]
    fn high_severity_escalates_a_review_to_a_hold() {
        let mut assessment = quiet();
        assessment.answers.insert(
            battery::BEYOND_TASK.to_string(),
            Answer::boolean(0.5, Calibration::Calibrated { source: "t".into() }),
        );
        assessment.answers.insert(
            battery::SEVERITY.to_string(),
            Answer::level(1.0, 0.9, Calibration::Calibrated { source: "t".into() }),
        );
        assert_eq!(
            route(&state(), &assessment, &Policy::default()).action(),
            Action::Hold
        );
    }

    #[test]
    fn an_empty_change_set_needs_no_review() {
        let empty = ChangeSetState {
            task: None,
            changes: vec![],
            precomputed: Default::default(),
        };
        let decision = route(&empty, &Assessment::empty("none"), &Policy::default());
        assert_eq!(decision.action(), Action::AutoApply);
    }

    /// Hard rules are checked before anything else, so a change set that trips
    /// one is held even when every question came back clean.
    #[test]
    fn hard_rules_are_not_overridable_by_answers() {
        let mut state = state();
        state.precomputed.max_shrink_ratio = 0.99;
        let decision = route(&state, &quiet(), &Policy::default());
        assert_eq!(decision.action(), Action::Hold);
        assert!(!decision.rationale().hard_rules.is_empty());
    }
}
