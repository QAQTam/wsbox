//! The assessor boundary — the seam that keeps the vendor out.
//!
//! Everything above this line (`Battery`, `Answer`, `Policy`, `Decision`) is
//! vendor-neutral. Everything below it is a backend: a hosted decision model
//! today, a local classifier tomorrow, a rules pass always.
//!
//! An assessor answers *some* of the battery. It is not required to answer all
//! of it, and it is not required to succeed. Both of those are deliberate: the
//! chain tries backends in order, and whatever is left unanswered becomes a
//! reason to ask a human rather than a reason to guess.

use std::collections::BTreeMap;

use crate::question::{Assessment, BackendFailure, Battery, QuestionId};
use crate::state::ChangeSetState;

#[derive(Debug, thiserror::Error)]
pub enum AssessorError {
    #[error("no API key configured")]
    NoApiKey,

    /// The credential is present but rejected. This is the expired-key case, and
    /// it must be distinguishable from a transient failure so the caller can say
    /// something useful instead of retrying forever.
    #[error("authentication rejected: {0}")]
    Unauthorized(String),

    #[error("rate limited")]
    RateLimited,

    #[error("network error: {0}")]
    Network(String),

    #[error("timed out")]
    Timeout,

    #[error("malformed response: {0}")]
    Malformed(String),

    /// A locally trained backend only answers the battery it was trained on.
    /// A mismatch is not an error to retry — it is a signal to fall back.
    #[error("battery {battery} is not supported by {assessor}")]
    UnsupportedBattery { assessor: String, battery: String },
}

pub type Result<T> = std::result::Result<T, AssessorError>;

/// A backend that can answer questions about a change set.
pub trait Assessor: Send + Sync {
    /// Stable identifier, used in the audit record.
    fn id(&self) -> &str;

    /// The concrete model version, when there is one. Pinned in the audit record
    /// so thresholds can be re-tuned when the model moves under you.
    fn model(&self) -> Option<String> {
        None
    }

    /// Which batteries this backend can answer.
    ///
    /// A hosted model answers anything. A local classifier answers exactly the
    /// fingerprint it was trained on, and returning `false` for anything else is
    /// the whole reason this method exists.
    fn supports(&self, battery: &Battery) -> bool;

    /// Answer as much of `battery` as this backend can.
    ///
    /// Returning fewer answers than questions is normal and not an error — the
    /// chain passes the remainder to the next backend.
    fn assess(
        &self,
        state: &ChangeSetState,
        battery: &Battery,
    ) -> Result<BTreeMap<QuestionId, crate::question::Answer>>;
}

/// Runs assessors in order, giving each one only the questions still unanswered.
///
/// The rules pass goes first because it is free, offline, and exact. A model is
/// consulted only for what the rules could not decide — which is also why an
/// API outage degrades to "ask a human" rather than "guess".
pub struct Chain {
    assessors: Vec<Box<dyn Assessor>>,
}

impl Chain {
    pub fn new(assessors: Vec<Box<dyn Assessor>>) -> Self {
        Self { assessors }
    }

    pub fn assess(&self, state: &ChangeSetState, battery: &Battery) -> Assessment {
        let mut assessment = Assessment::empty("chain");
        let mut remaining: Vec<QuestionId> =
            battery.questions.iter().map(|q| q.id.clone()).collect();
        let mut models = Vec::new();

        for assessor in &self.assessors {
            if remaining.is_empty() {
                break;
            }
            let id = assessor.id().to_string();

            if !assessor.supports(battery) {
                assessment.failures.push(BackendFailure {
                    assessor: id.clone(),
                    reason: format!(
                        "does not support battery {} (fingerprint {})",
                        battery.id,
                        battery.fingerprint()
                    ),
                });
                continue;
            }

            let subset = Battery {
                id: battery.id.clone(),
                version: battery.version,
                questions: battery
                    .questions
                    .iter()
                    .filter(|question| remaining.contains(&question.id))
                    .cloned()
                    .collect(),
            };

            match assessor.assess(state, &subset) {
                Ok(answers) => {
                    if let Some(model) = assessor.model() {
                        models.push(model);
                    }
                    for (question_id, answer) in answers {
                        assessment.answers.insert(question_id.clone(), answer);
                        remaining.retain(|id| id != &question_id);
                    }
                }
                Err(error) => {
                    // A failure is recorded, not fatal. Whatever the earlier
                    // assessors answered still counts, and the questions this one
                    // would have answered stay unanswered — which the router
                    // turns into a human decision.
                    assessment.failures.push(BackendFailure {
                        assessor: id,
                        reason: error.to_string(),
                    });
                }
            }
        }

        assessment.assessor = self
            .assessors
            .first()
            .map(|a| a.id().to_string())
            .unwrap_or_else(|| "none".into());
        assessment.model = if models.is_empty() {
            None
        } else {
            Some(models.join("+"))
        };
        assessment.unanswered = remaining;
        assessment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::battery;
    use crate::question::{Answer, Calibration, Question};

    struct Fixed {
        id: &'static str,
        answers: Vec<QuestionId>,
        fail: Option<AssessorError>,
    }

    impl Assessor for Fixed {
        fn id(&self) -> &str {
            self.id
        }
        fn supports(&self, _battery: &Battery) -> bool {
            true
        }
        fn assess(
            &self,
            _state: &ChangeSetState,
            battery: &Battery,
        ) -> Result<BTreeMap<QuestionId, Answer>> {
            if let Some(error) = &self.fail {
                return Err(match error {
                    AssessorError::Network(message) => AssessorError::Network(message.clone()),
                    other => AssessorError::Malformed(other.to_string()),
                });
            }
            Ok(battery
                .questions
                .iter()
                .filter(|question| self.answers.contains(&question.id))
                .map(|question| {
                    (
                        question.id.clone(),
                        Answer::boolean(0.1, Calibration::Exact),
                    )
                })
                .collect())
        }
    }

    struct Pinned {
        fingerprint: String,
    }

    impl Assessor for Pinned {
        fn id(&self) -> &str {
            "pinned"
        }
        fn supports(&self, battery: &Battery) -> bool {
            battery.fingerprint() == self.fingerprint
        }
        fn assess(
            &self,
            _state: &ChangeSetState,
            battery: &Battery,
        ) -> Result<BTreeMap<QuestionId, Answer>> {
            Ok(battery
                .questions
                .iter()
                .map(|question| {
                    (
                        question.id.clone(),
                        Answer::boolean(0.1, Calibration::Exact),
                    )
                })
                .collect())
        }
    }

    fn state() -> ChangeSetState {
        ChangeSetState::from_changes(None, &[])
    }

    #[test]
    fn later_assessors_only_see_what_is_left() {
        let battery = battery::change_set();
        let chain = Chain::new(vec![
            Box::new(Fixed {
                id: "first",
                answers: vec![battery::LOST_CONTENT.to_string()],
                fail: None,
            }),
            Box::new(Fixed {
                id: "second",
                answers: battery.questions.iter().map(|q| q.id.clone()).collect(),
                fail: None,
            }),
        ]);

        let assessment = chain.assess(&state(), &battery);
        assert_eq!(
            assessment.answers.len(),
            battery.questions.len(),
            "the chain must fill every question it can"
        );
    }

    #[test]
    fn a_failing_backend_leaves_its_questions_unanswered() {
        let battery = battery::change_set();
        let chain = Chain::new(vec![Box::new(Fixed {
            id: "down",
            answers: vec![],
            fail: Some(AssessorError::Unauthorized("expired".into())),
        })]);

        let assessment = chain.assess(&state(), &battery);
        assert!(assessment.answers.is_empty());
        assert_eq!(assessment.unanswered.len(), battery.questions.len());
        assert_eq!(assessment.failures.len(), 1);
        assert!(
            assessment.failures[0].reason.contains("expired"),
            "the failure reason must survive into the audit record"
        );
    }

    #[test]
    fn a_pinned_backend_declines_a_changed_battery() {
        let battery = battery::change_set();
        let mut other = battery.clone();
        other.questions.push(Question::boolean("extra", "?"));

        let chain = Chain::new(vec![Box::new(Pinned {
            fingerprint: battery.fingerprint(),
        })]);

        let assessment = chain.assess(&state(), &other);
        assert!(assessment.answers.is_empty());
        assert!(
            assessment.failures[0].reason.contains("does not support"),
            "a stale local model must decline rather than misanswer"
        );
    }
}
