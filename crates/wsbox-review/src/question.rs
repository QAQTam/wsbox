//! Questions, answers, and the battery that groups them.
//!
//! This is the layer that makes the component vendor-neutral. A backend is
//! anything that can answer *some* of these questions — a hosted decision model,
//! a local classifier, or a deterministic rules pass. Nothing here mentions a
//! vendor.
//!
//! The shape is deliberately borrowed from how calibrated decision models are
//! queried, because the alternative (asking an LLM to "return a number") gives
//! you a number with no statistical meaning, and a threshold on a meaningless
//! number is worse than no threshold at all.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub type QuestionId = String;

/// What kind of judgment a question asks for.
///
/// Kept to three shapes on purpose: every backend we care about — hosted
/// decision model, local classifier head, rules engine — can express its output
/// as one of these.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QuestionKind {
    /// "Is this statement true?" — the answer is a probability in `0..=1`.
    Boolean,
    /// Rate the state against ordered, descriptive levels.
    Rubric { levels: Vec<String> },
    /// Pick one of a fixed set of options.
    Category { options: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Question {
    pub id: QuestionId,
    pub kind: QuestionKind,
    pub instructions: String,
}

impl Question {
    pub fn boolean(id: &str, instructions: &str) -> Self {
        Self {
            id: id.to_string(),
            kind: QuestionKind::Boolean,
            instructions: instructions.to_string(),
        }
    }

    pub fn rubric(id: &str, instructions: &str, levels: &[&str]) -> Self {
        Self {
            id: id.to_string(),
            kind: QuestionKind::Rubric {
                levels: levels.iter().map(|s| s.to_string()).collect(),
            },
            instructions: instructions.to_string(),
        }
    }

    pub fn category(id: &str, instructions: &str, options: &[&str]) -> Self {
        Self {
            id: id.to_string(),
            kind: QuestionKind::Category {
                options: options.iter().map(|s| s.to_string()).collect(),
            },
            instructions: instructions.to_string(),
        }
    }
}

/// A named, versioned set of questions.
///
/// The version is not decoration. A locally trained classifier's output head is
/// fixed at training time, so it can only answer the battery it was trained
/// against. `fingerprint` is what an assessor declares support for, and a
/// mismatch is a fallback trigger rather than a silent misanswer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Battery {
    pub id: String,
    pub version: u32,
    pub questions: Vec<Question>,
}

impl Battery {
    pub fn get(&self, id: &str) -> Option<&Question> {
        self.questions.iter().find(|question| question.id == id)
    }

    /// Stable digest over the battery's identity and its questions.
    pub fn fingerprint(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(self.id.as_bytes());
        hasher.update(self.version.to_le_bytes());
        for question in &self.questions {
            hasher.update(question.id.as_bytes());
            hasher.update(question.instructions.as_bytes());
            match &question.kind {
                QuestionKind::Boolean => hasher.update(b"bool"),
                QuestionKind::Rubric { levels } => {
                    hasher.update(b"rubric");
                    for level in levels {
                        hasher.update(level.as_bytes());
                    }
                }
                QuestionKind::Category { options } => {
                    hasher.update(b"category");
                    for option in options {
                        hasher.update(option.as_bytes());
                    }
                }
            }
        }
        format!("{:x}", hasher.finalize())[..16].to_string()
    }
}

/// Whether a backend's numbers mean what they say.
///
/// This is the load-bearing distinction in the whole component. A calibrated
/// probability of 0.7 means "70% of cases like this turned out true". A raw
/// classifier logit of 0.7 means nothing in particular, and thresholding it
/// directly produces a policy you cannot reason about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Calibration {
    /// Deterministic: exactly 0.0 or 1.0, no uncertainty to calibrate.
    Exact,
    /// The backend discharged calibration itself — either it is natively
    /// calibrated, or it applies a map fitted on labelled data.
    Calibrated { source: String },
    /// Raw model output. Thresholds are not meaningful, so the router refuses to
    /// auto-apply from this answer.
    Uncalibrated,
}

impl Calibration {
    pub fn is_trustworthy(&self) -> bool {
        matches!(self, Calibration::Exact | Calibration::Calibrated { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Answer {
    /// Boolean questions: the probability that the statement holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probability: Option<f64>,
    /// Rubric questions: the level, normalised to `0..=1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<f64>,
    /// Category questions: the chosen option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The full distribution, when the backend provides one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distribution: Option<Vec<f64>>,
    /// How sure the backend is of its own answer.
    ///
    /// `None` means "cannot say" — which is not the same as "very sure". A
    /// backend that cannot express uncertainty cannot be trusted to act alone,
    /// so the router treats a missing value as a reason to escalate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub calibration: Calibration,
}

impl Answer {
    pub fn boolean(probability: f64, calibration: Calibration) -> Self {
        Self {
            probability: Some(probability),
            level: None,
            category: None,
            distribution: None,
            confidence: None,
            calibration,
        }
    }

    pub fn level(level: f64, confidence: f64, calibration: Calibration) -> Self {
        Self {
            probability: None,
            level: Some(level),
            category: None,
            distribution: None,
            confidence: Some(confidence),
            calibration,
        }
    }

    pub fn category(category: &str, confidence: f64, calibration: Calibration) -> Self {
        Self {
            probability: None,
            level: None,
            category: Some(category.to_string()),
            distribution: None,
            confidence: Some(confidence),
            calibration,
        }
    }
}

/// A backend's answers to as much of a battery as it could answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    /// Which assessor produced the bulk of this. `rules` for the deterministic
    /// pass, a backend id otherwise.
    pub assessor: String,
    /// The concrete model version, when there is one. Pinned in the audit record
    /// so thresholds can be re-tuned when the model moves.
    pub model: Option<String>,
    pub answers: BTreeMap<QuestionId, Answer>,
    /// Questions the chain tried to answer and could not.
    pub unanswered: Vec<QuestionId>,
    /// Backends that were tried and failed, with the reason. Carried through so
    /// "why did this need a human?" has an answer in the audit record.
    pub failures: Vec<BackendFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendFailure {
    pub assessor: String,
    pub reason: String,
}

impl Assessment {
    pub fn empty(assessor: &str) -> Self {
        Self {
            assessor: assessor.to_string(),
            model: None,
            answers: BTreeMap::new(),
            unanswered: Vec::new(),
            failures: Vec::new(),
        }
    }

    pub fn answer(&self, id: &str) -> Option<&Answer> {
        self.answers.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_changes_with_the_battery() {
        let mut battery = crate::battery::change_set();
        let before = battery.fingerprint();
        battery.questions[0].instructions.push_str(" (revised)");
        assert_ne!(before, battery.fingerprint());
    }

    #[test]
    fn fingerprint_is_stable_for_the_same_battery() {
        assert_eq!(
            crate::battery::change_set().fingerprint(),
            crate::battery::change_set().fingerprint()
        );
    }

    #[test]
    fn uncalibrated_is_not_trustworthy() {
        assert!(!Calibration::Uncalibrated.is_trustworthy());
        assert!(Calibration::Exact.is_trustworthy());
        assert!(
            Calibration::Calibrated {
                source: "jev".into()
            }
            .is_trustworthy()
        );
    }
}
