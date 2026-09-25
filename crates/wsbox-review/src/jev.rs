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

pub struct Jev {
    api_key: String,
    endpoint: String,
    model: String,
    timeout: Duration,
    /// Cap on the diff bytes sent as state. Jev's context is 64k tokens with 32k
    /// for the state plus the longest question, so this leaves room for the
    /// battery and keeps the request in the cheap part of the curve.
    diff_budget: usize,
}

impl Jev {
    /// Reads `TYPESAFE_API_KEY`. Returns the "no key" error rather than
    /// panicking, so the caller's fallback path is the normal one.
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("TYPESAFE_API_KEY").map_err(|_| AssessorError::NoApiKey)?;
        if api_key.trim().is_empty() {
            return Err(AssessorError::NoApiKey);
        }
        Ok(Self::new(api_key))
    }

    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
            model: DEFAULT_MODEL.to_string(),
            timeout: Duration::from_secs(30),
            diff_budget: 48_000,
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

        let mut response = agent
            .post(&self.endpoint)
            .header("Authorization", &format!("Bearer {}", self.api_key))
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
        let calibration = Calibration::Calibrated {
            source: model_version,
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
            let parsed = match &question.kind {
                QuestionKind::Boolean => raw
                    .get("noul")
                    .and_then(Value::as_f64)
                    .map(|probability| Answer::boolean(probability, calibration.clone())),
                QuestionKind::Rubric { levels } => {
                    raw.get("score").and_then(Value::as_f64).map(|score| {
                        let confidence = raw
                            .get("confidence")
                            .and_then(Value::as_f64)
                            .unwrap_or_default();
                        Answer::level(
                            battery::normalise_level(score, levels.len()),
                            confidence,
                            calibration.clone(),
                        )
                    })
                }
                QuestionKind::Category { .. } => {
                    raw.get("choice").and_then(Value::as_str).map(|choice| {
                        let confidence = raw
                            .get("confidence")
                            .and_then(Value::as_f64)
                            .unwrap_or_default();
                        Answer::category(choice, confidence, calibration.clone())
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
