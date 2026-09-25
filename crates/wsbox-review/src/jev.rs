//! The TypeSafe (Jev) assessor — the first hosted backend.
//!
//! Behind the `jev` feature so that `wsbox-review`'s core, and `wsbox` itself,
//! carry no network stack and no vendor dependency. The whole point of the
//! `Assessor` seam is that this file is replaceable.
//!
//! What makes Jev a good fit here, and why it is not simply "call an LLM to
//! review the diff":
//!
//! * its probabilities are calibrated, so a threshold on them means something;
//! * it answers the whole battery in one request, in parallel;
//! * it does not generate prose, so there is no reasoning chain for a diff to
//!   talk its way past.
//!
//! What it is *not*: a boundary. Everything it says passes through the hard
//! rules in [`crate::policy`] first, and a change to `.github/` is held whatever
//! Jev thinks of it.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Value, json};

use crate::assessor::{Assessor, AssessorError, Result};
use crate::battery;
use crate::question::{Answer, Battery, Calibration, QuestionId, QuestionKind};
use crate::state::ChangeSetState;

pub const DEFAULT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
pub const DEFAULT_MODEL: &str = "jev-latest";

/// What a backend claims about its own probabilities.
///
/// This is not a formality. A hosted Jev is trained with RLCD against strictly
/// proper scoring rules, so its probabilities are calibrated and a threshold on
/// them means something. A self-hosted open checkpoint is not: Laya's own model
/// card reports a mean ECE of 0.466 out of the box, improving to 0.081 only
/// after fitting a temperature per question type on your data.
///
/// So the default for a self-hosted endpoint is [`CalibrationClaim::Raw`], and
/// the router refuses to auto-apply from raw output. Claiming otherwise has to
/// be a deliberate act performed after fitting temperatures — which is the
/// correct order of operations, not a hoop to jump through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalibrationClaim {
    /// Natively calibrated; the vendor's training procedure guarantees it.
    Native,
    /// A calibration map was fitted on this deployment's own labelled data.
    Fitted { source: String },
    /// Raw model output. Thresholds do not apply.
    Raw,
}

pub struct Jev {
    api_key: String,
    endpoint: String,
    model: String,
    timeout: Duration,
    /// Cap on the diff bytes sent as state. Jev's context is 64k tokens with 32k
    /// for the state plus the longest question, so this leaves room for the
    /// battery and keeps the request in the cheap part of the curve.
    diff_budget: usize,
    calibration: CalibrationClaim,
}

impl Jev {
    /// Reads `TYPESAFE_ENDPOINT` and `TYPESAFE_API_KEY`.
    ///
    /// The endpoint override is what makes a self-hosted model a drop-in: Laya's
    /// `laya-serve` speaks the same `POST /v1/systemone` wire protocol with a
    /// schema-identical payload, so pointing this at it is the whole
    /// integration. A self-hosted instance usually has no auth, so a missing key
    /// is only an error for the hosted endpoint.
    ///
    /// Returns the "no key" error rather than panicking, so the caller's
    /// fallback path is the normal one.
    pub fn from_env() -> Result<Self> {
        let endpoint = non_empty(std::env::var("TYPESAFE_ENDPOINT").ok());
        let api_key = non_empty(std::env::var("TYPESAFE_API_KEY").ok());

        match (endpoint, api_key) {
            (Some(endpoint), key) => Ok(Self::new(key.unwrap_or_default())
                .with_endpoint(endpoint)
                // Fail closed: a self-hosted endpoint is raw until someone fits
                // temperatures and says otherwise. `WSBOX_REVIEW_CALIBRATION`
                // is the deliberate act of saying otherwise.
                .with_calibration(calibration_from_env())),
            (None, Some(key)) => Ok(Self::new(key)),
            (None, None) => Err(AssessorError::NoApiKey),
        }
    }

    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
            model: DEFAULT_MODEL.to_string(),
            timeout: Duration::from_secs(30),
            diff_budget: 48_000,
            calibration: CalibrationClaim::Native,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_diff_budget(mut self, bytes: usize) -> Self {
        self.diff_budget = bytes;
        self
    }

    pub fn with_calibration(mut self, claim: CalibrationClaim) -> Self {
        self.calibration = claim;
        self
    }

    fn request_body(&self, state: &ChangeSetState, battery: &Battery) -> Value {
        let questions: serde_json::Map<String, Value> = battery
            .questions
            .iter()
            .map(|question| {
                let body = match &question.kind {
                    QuestionKind::Boolean => json!({
                        "type": "noul",
                        "instructions": question.instructions,
                    }),
                    QuestionKind::Rubric { levels } => json!({
                        "type": "score",
                        "instructions": question.instructions,
                        "criteria": levels,
                    }),
                    QuestionKind::Category { options } => json!({
                        "type": "choice",
                        "instructions": question.instructions,
                        "criteria": options
                            .iter()
                            .map(|option| (option.clone(), Value::Null))
                            .collect::<serde_json::Map<String, Value>>(),
                    }),
                };
                (question.id.clone(), body)
            })
            .collect();

        json!({
            "model": self.model,
            "state": state,
            "questions": questions,
        })
    }

    fn call(&self, body: &Value) -> Result<Value> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            // Status codes are handled here rather than thrown, so a 401 can be
            // reported as "the key expired" instead of a generic transport
            // error.
            .http_status_as_error(false)
            .build()
            .into();

        let mut request = agent.post(&self.endpoint);
        // A self-hosted instance usually runs without auth, so the header is
        // only sent when there is something to send.
        if !self.api_key.is_empty() {
            request = request.header("Authorization", &format!("Bearer {}", self.api_key));
        }
        let mut response = request
            .header("Content-Type", "application/json")
            .send_json(body)
            .map_err(|error| match error {
                ureq::Error::Timeout(_) => AssessorError::Timeout,
                other => AssessorError::Network(other.to_string()),
            })?;

        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|error| AssessorError::Network(error.to_string()))?;

        match status {
            200..=299 => serde_json::from_str(&text)
                .map_err(|error| AssessorError::Malformed(error.to_string())),
            401 | 403 => Err(AssessorError::Unauthorized(excerpt(&text))),
            429 => Err(AssessorError::RateLimited),
            _ => Err(AssessorError::Malformed(format!(
                "HTTP {status}: {}",
                excerpt(&text)
            ))),
        }
    }
}

/// Read the operator's explicit claim about a self-hosted endpoint.
///
/// Defaults to `raw`, because the safe assumption about an arbitrary checkpoint
/// is that its numbers are not yet meaningful.
fn calibration_from_env() -> CalibrationClaim {
    match non_empty(std::env::var("WSBOX_REVIEW_CALIBRATION").ok()).as_deref() {
        Some("native") => CalibrationClaim::Native,
        Some(value) if value.starts_with("fitted:") => CalibrationClaim::Fitted {
            source: value.trim_start_matches("fitted:").to_string(),
        },
        _ => CalibrationClaim::Raw,
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

fn excerpt(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= 200 {
        return trimmed.to_string();
    }
    trimmed.chars().take(200).collect::<String>() + "..."
}

impl Assessor for Jev {
    fn id(&self) -> &str {
        "jev"
    }

    fn model(&self) -> Option<String> {
        Some(self.model.clone())
    }

    /// A hosted model answers any battery. A local classifier will not, and that
    /// is the difference this method exists to express.
    fn supports(&self, _battery: &Battery) -> bool {
        true
    }

    fn assess(
        &self,
        state: &ChangeSetState,
        battery: &Battery,
    ) -> Result<BTreeMap<QuestionId, Answer>> {
        // Send a copy with the diffs trimmed to fit. `trim_diffs` also records
        // that it trimmed, and the caller's policy sees that flag — so a
        // partially-seen change set escalates rather than auto-applies.
        let mut payload = state.clone();
        payload.trim_diffs(self.diff_budget);

        let body = self.request_body(&payload, battery);
        let response = self.call(&body)?;

        let model_version = response
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(&self.model)
            .to_string();
        // What the backend claims about itself decides whether the router may
        // threshold its numbers at all. A self-hosted checkpoint that has not
        // been temperature-fitted says `Raw`, and raw answers never auto-apply.
        let calibration = match &self.calibration {
            CalibrationClaim::Native => Calibration::Calibrated {
                source: model_version,
            },
            CalibrationClaim::Fitted { source } => Calibration::Calibrated {
                source: format!("{model_version}+{source}"),
            },
            CalibrationClaim::Raw => Calibration::Uncalibrated,
        };

        let answers = response
            .get("answers")
            .and_then(Value::as_object)
            .ok_or_else(|| AssessorError::Malformed("response has no `answers`".into()))?;

        let mut out = BTreeMap::new();
        for question in &battery.questions {
            let Some(raw) = answers.get(&question.id) else {
                // Not every question is guaranteed an answer. Leaving it out is
                // correct: the router turns a missing answer into a human.
                continue;
            };

            // The full distribution, ordered to match the question's own option
            // order. This is the training target: distilling a decision model
            // needs the distribution, not just the argmax, and dropping it here
            // would make the corpus unusable for that later.
            let distribution = ordered_distribution(raw, &question.kind);

            let parsed = match &question.kind {
                QuestionKind::Boolean => {
                    raw.get("noul")
                        .and_then(Value::as_f64)
                        .map(|probability| Answer {
                            distribution,
                            ..Answer::boolean(probability, calibration.clone())
                        })
                }
                QuestionKind::Rubric { levels } => {
                    raw.get("score").and_then(Value::as_f64).map(|score| {
                        let confidence = raw
                            .get("confidence")
                            .and_then(Value::as_f64)
                            .unwrap_or_default();
                        Answer {
                            distribution,
                            ..Answer::level(
                                battery::normalise_level(score, levels.len()),
                                confidence,
                                calibration.clone(),
                            )
                        }
                    })
                }
                QuestionKind::Category { .. } => {
                    raw.get("choice").and_then(Value::as_str).map(|choice| {
                        let confidence = raw
                            .get("confidence")
                            .and_then(Value::as_f64)
                            .unwrap_or_default();
                        Answer {
                            distribution,
                            ..Answer::category(choice, confidence, calibration.clone())
                        }
                    })
                }
            };
            if let Some(answer) = parsed {
                out.insert(question.id.clone(), answer);
            }
        }

        Ok(out)
    }
}

/// Pull `probabilities` out of a response and order it to match the question.
///
/// The wire format keys the distribution by label — the option names for a
/// choice, `"0".."n"` for a score — while a training target is a plain vector.
/// Ordering it here, against the question the request was built from, is what
/// makes the two agree.
///
/// A `noul` is the exception: neither Jev nor Laya returns a distribution for
/// one, only the scalar `noul` probability. It is reconstructed as
/// `[1 - p, p]`, which is exact for a binary rather than an approximation — but
/// it does mean a noul carries strictly less information than a choice, and a
/// corpus built from nouls cannot teach a distribution the teacher never had.
fn ordered_distribution(raw: &Value, kind: &QuestionKind) -> Option<Vec<f64>> {
    let probabilities = raw.get("probabilities").and_then(Value::as_object);

    let ordered = match kind {
        QuestionKind::Boolean => {
            if let Some(probabilities) = probabilities {
                vec![
                    probabilities.get("false").and_then(Value::as_f64)?,
                    probabilities.get("true").and_then(Value::as_f64)?,
                ]
            } else {
                let yes = raw.get("noul").and_then(Value::as_f64)?;
                vec![1.0 - yes, yes]
            }
        }
        QuestionKind::Rubric { levels } => {
            let probabilities = probabilities?;
            (0..levels.len())
                .map(|index| {
                    probabilities
                        .get(&index.to_string())
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0)
                })
                .collect()
        }
        QuestionKind::Category { options } => {
            let probabilities = probabilities?;
            options
                .iter()
                .map(|option| {
                    probabilities
                        .get(option)
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0)
                })
                .collect()
        }
    };
    Some(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_key_is_an_error_not_a_panic() {
        // The environment may legitimately have the variable set; the point is
        // only that the call returns rather than panicking.
        let _ = Jev::from_env();
    }

    #[test]
    fn the_request_body_maps_each_primitive() {
        let jev = Jev::new("test-key");
        let battery = battery::change_set();
        let state = ChangeSetState::from_changes(None, &[]);
        let body = jev.request_body(&state, &battery);

        assert_eq!(body["model"], "jev-latest");
        assert_eq!(body["questions"][battery::LOST_CONTENT]["type"], "noul");
        assert_eq!(body["questions"][battery::SEVERITY]["type"], "score");
        assert_eq!(body["questions"][battery::CATEGORY]["type"], "choice");
        assert!(
            body["questions"][battery::SEVERITY]["criteria"]
                .as_array()
                .is_some_and(|levels| levels.len() == 4)
        );
        assert!(
            body["questions"][battery::CATEGORY]["criteria"]
                .as_object()
                .is_some_and(|options| options.len() == 6)
        );
    }

    #[test]
    fn state_carries_the_precomputed_facts() {
        let jev = Jev::new("test-key");
        let mut state = ChangeSetState::from_changes(Some("fix the parser".into()), &[]);
        state.precomputed.max_shrink_ratio = 0.9;
        let body = jev.request_body(&state, &battery::change_set());

        assert_eq!(body["state"]["task"], "fix the parser");
        assert_eq!(body["state"]["precomputed"]["maxShrinkRatio"], 0.9);
    }
}
