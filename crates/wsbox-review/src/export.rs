//! Auditable CSV export of review history.
//!
//! # What this is for
//!
//! Swapping the hosted model for a local one needs data, and the review log is
//! where it comes from. But "the log" and "a training set" are not the same
//! thing, and the difference decides the schema.
//!
//! There are three things you can train, and they need different labels:
//!
//! | Target | Label | Density | Catch |
//! |---|---|---|---|
//! | Distil the hosted model | its per-question answers | every row | inherits its biases |
//! | Fit a calibration map | the human outcome | every resolved row | needs resolution |
//! | Train heads directly | the human outcome | every resolved row | a *weak* label |
//!
//! The third one is the trap. A human accept/reject is a label on the **change
//! set**, but the battery asks eight separate questions. "A person rejected
//! this" tells you at least one hazard was present; it does not tell you which.
//! Training six boolean heads on that label directly is multiple-instance
//! learning wearing a binary-classification hat, and it will teach the heads to
//! fire indiscriminately.
//!
//! So the CSV carries both labels side by side and says which is which:
//! `q_*` columns are the model's answers, `human_outcome` is the person's. A
//! consumer that wants to distil uses the former; one that wants to calibrate
//! uses the latter against `assessed_action`; one that wants to train heads
//! directly has to reckon with the weakness, and the column layout at least
//! makes that visible instead of hiding it.
//!
//! # What makes it auditable
//!
//! Each row carries a digest chained to the previous row, over a canonical
//! serialisation of that row's fields. Editing any cell breaks the chain, and
//! `verify_csv` says where. Every row also points back at the wsbox ledger head
//! it was taken under, so a row can be traced to the change set it describes.
//!
//! The CSV is a *derived* artefact. `review.jsonl` remains the source of truth;
//! the export is reproducible from it, and the chain is what makes the derived
//! copy worth trusting.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::battery;
use crate::question::Battery;
use crate::state::PrecomputedFacts;

/* --------------------------------- records ------------------------------- */

/// One line of `review.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LogEntry {
    Review(Box<ReviewRecord>),
    Resolution(ResolutionRecord),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRecord {
    pub review_id: u64,
    pub at_ms: u64,
    pub mode: String,
    #[serde(default)]
    pub shadow: bool,
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub call: Option<String>,
    /// The `Decision`, carried opaquely: `Decision` is deliberately
    /// serialize-only so that nothing can construct an `AutoApply` from JSON.
    /// The export reads it through accessors rather than deserialising it.
    pub decision: serde_json::Value,
    pub assessed_action: String,
    pub battery_fingerprint: String,
    /// The policy in force. Without it a decision cannot be replayed, and "why
    /// was this auto-approved?" has no answer.
    #[serde(default)]
    pub policy: serde_json::Value,
    /// The wsbox ledger chain head when this review ran, so the row can be tied
    /// back to the change set it describes.
    #[serde(default)]
    pub ledger_head: Option<String>,
    pub precomputed: PrecomputedFacts,
    /// The change set under review, per file.
    ///
    /// Stored structurally rather than as one concatenated blob because the
    /// training exporter has to rebuild the exact `state` that was sent, and a
    /// flattened string cannot be taken apart again.
    #[serde(default)]
    pub changes: Vec<crate::state::ChangeSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionRecord {
    pub review_id: u64,
    pub at_ms: u64,
    pub human_outcome: String,
    #[serde(default)]
    pub note: Option<String>,
}

impl LogEntry {
    pub fn parse(text: &str) -> Result<Vec<LogEntry>, String> {
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).map_err(|error| format!("corrupt log line: {error}"))
            })
            .collect()
    }
}

/// Concatenate a change set's diffs into one blob for the log.
pub fn concat_diffs(changes: &[crate::state::ChangeSummary]) -> Option<String> {
    let mut out = String::new();
    for change in changes {
        let Some(diff) = &change.diff else {
            continue;
        };
        out.push_str(&format!(
            "### file: {} ({})\n",
            change.path,
            op_name(change.op)
        ));
        out.push_str(diff);
        if !diff.ends_with('\n') {
            out.push('\n');
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn op_name(op: wsbox::protocol::Op) -> &'static str {
    match op {
        wsbox::protocol::Op::Add => "add",
        wsbox::protocol::Op::Modify => "modify",
        wsbox::protocol::Op::Delete => "delete",
        wsbox::protocol::Op::Chmod => "chmod",
    }
}

/* ---------------------------------- rows --------------------------------- */

/// Fields of one exported row, keyed by column name.
///
/// A `BTreeMap` so the canonical serialisation used for the digest is
/// order-stable regardless of insertion order.
pub type Fields = BTreeMap<String, String>;

#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Embed the diff. Off gives a compact audit-only table.
    pub include_diffs: bool,
}

/// Columns that exist regardless of the battery.
const BASE_COLUMNS: &[&str] = &[
    "row_index",
    "prev_row_hash",
    "row_hash",
    "session_id",
    "review_id",
    "call_id",
    "ledger_head",
    "battery_id",
    "battery_version",
    "battery_fingerprint",
    "assessor",
    "model",
    "mode",
    "shadow",
    "created_at_ms",
    "resolved_at_ms",
    "resolved",
    "human_outcome",
    "human_note",
    "assessed_action",
    "may_auto_apply",
    "hard_rule_count",
    "hard_rules",
    "fallback_count",
    "fallback_kinds",
    "fired_hazards",
    "task",
    "files_changed",
    "files_added",
    "files_deleted",
    "max_shrink_ratio",
    "sensitive_path_count",
    "sensitive_paths",
    "any_diff_truncated",
    "diff_bytes",
    "diff_sha256",
];

const DIFF_COLUMN: &str = "diff";

/// Per-question columns, generated so the table stays aligned with the battery.
fn question_columns(battery: &Battery) -> Vec<String> {
    let mut out = Vec::new();
    for question in &battery.questions {
        let prefix = format!("q_{}", question.id);
        match &question.kind {
            crate::question::QuestionKind::Boolean => out.push(format!("{prefix}_p")),
            crate::question::QuestionKind::Rubric { .. } => {
                out.push(format!("{prefix}_level"));
            }
            crate::question::QuestionKind::Category { .. } => {
                out.push(format!("{prefix}_category"));
            }
        }
        out.push(format!("{prefix}_confidence"));
        out.push(format!("{prefix}_calibration"));
    }
    out
}

/* --------------------------------- export -------------------------------- */

#[derive(Debug, Clone)]
pub struct ExportReport {
    pub csv: String,
    pub rows: usize,
    pub resolved: usize,
    pub head: String,
}

/// One session's records, with the id used in the `session_id` column.
pub struct SessionLog {
    pub session_id: String,
    pub entries: Vec<LogEntry>,
}

pub fn export(sessions: &[SessionLog], options: &ExportOptions) -> Result<ExportReport, String> {
    let battery = battery::change_set();
    let mut columns: Vec<String> = BASE_COLUMNS.iter().map(|c| c.to_string()).collect();
    columns.extend(question_columns(&battery));
    if options.include_diffs {
        columns.push(DIFF_COLUMN.to_string());
    }

    let mut rows: Vec<Fields> = Vec::new();
    let mut resolved_count = 0usize;

    for session in sessions {
        let resolutions: BTreeMap<u64, &ResolutionRecord> = session
            .entries
            .iter()
            .filter_map(|entry| match entry {
                LogEntry::Resolution(resolution) => Some((resolution.review_id, resolution)),
                LogEntry::Review(_) => None,
            })
            .collect();

        // Stable ordering across sessions: by timestamp, then review id.
        let mut reviews: Vec<&ReviewRecord> = session
            .entries
            .iter()
            .filter_map(|entry| match entry {
                LogEntry::Review(record) => Some(record.as_ref()),
                LogEntry::Resolution(_) => None,
            })
            .collect();
        reviews.sort_by_key(|record| (record.at_ms, record.review_id));

        for record in reviews {
            let resolution = resolutions.get(&record.review_id);
            if resolution.is_some() {
                resolved_count += 1;
            }
            rows.push(build_row(
                &session.session_id,
                record,
                resolution.copied(),
                options,
            ));
        }
    }

    // Chain the rows. The digest covers the previous row's digest, so a
    // reordering is as detectable as an edit.
    let mut previous = "0".repeat(64);
    for (index, row) in rows.iter_mut().enumerate() {
        row.insert("row_index".into(), (index + 1).to_string());
        row.insert("prev_row_hash".into(), previous.clone());
        let digest = row_digest(row);
        row.insert("row_hash".into(), digest.clone());
        previous = digest;
    }

    let mut csv = String::new();
    csv.push_str(&columns.join(","));
    csv.push('\n');
    for row in &rows {
        let cells: Vec<String> = columns
            .iter()
            .map(|column| csv_field(row.get(column).map(String::as_str).unwrap_or("")))
            .collect();
        csv.push_str(&cells.join(","));
        csv.push('\n');
    }

    Ok(ExportReport {
        csv,
        rows: rows.len(),
        resolved: resolved_count,
        head: previous,
    })
}

fn build_row(
    session_id: &str,
    record: &ReviewRecord,
    resolution: Option<&ResolutionRecord>,
    options: &ExportOptions,
) -> Fields {
    let battery = battery::change_set();
    let mut row = Fields::new();
    row.insert("session_id".into(), session_id.to_string());
    row.insert("review_id".into(), record.review_id.to_string());
    row.insert("call_id".into(), record.call.clone().unwrap_or_default());
    row.insert(
        "ledger_head".into(),
        record.ledger_head.clone().unwrap_or_default(),
    );
    row.insert("battery_id".into(), battery::BATTERY_ID.to_string());
    row.insert(
        "battery_version".into(),
        battery::BATTERY_VERSION.to_string(),
    );
    row.insert(
        "battery_fingerprint".into(),
        record.battery_fingerprint.clone(),
    );

    let rationale = &record.decision["rationale"];
    row.insert(
        "assessor".into(),
        rationale["assessor"].as_str().unwrap_or("").to_string(),
    );
    row.insert(
        "model".into(),
        rationale["model"].as_str().unwrap_or("").to_string(),
    );
    row.insert("mode".into(), record.mode.clone());
    row.insert("shadow".into(), record.shadow.to_string());
    row.insert("created_at_ms".into(), record.at_ms.to_string());
    row.insert(
        "resolved_at_ms".into(),
        resolution.map(|r| r.at_ms.to_string()).unwrap_or_default(),
    );
    row.insert("resolved".into(), resolution.is_some().to_string());
    row.insert(
        "human_outcome".into(),
        resolution
            .map(|r| r.human_outcome.clone())
            .unwrap_or_default(),
    );
    row.insert(
        "human_note".into(),
        resolution.and_then(|r| r.note.clone()).unwrap_or_default(),
    );

    row.insert("assessed_action".into(), record.assessed_action.clone());
    row.insert(
        "may_auto_apply".into(),
        (record.assessed_action == "auto_apply" && !record.shadow).to_string(),
    );

    let hard_rules: Vec<String> = rationale["hardRules"]
        .as_array()
        .map(|rules| {
            rules
                .iter()
                .filter_map(|rule| rule.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    row.insert("hard_rule_count".into(), hard_rules.len().to_string());
    row.insert("hard_rules".into(), hard_rules.join("; "));

    let fallback_kinds: Vec<String> = rationale["fallbacks"]
        .as_array()
        .map(|fallbacks| {
            fallbacks
                .iter()
                .filter_map(|f| f["kind"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    row.insert("fallback_count".into(), fallback_kinds.len().to_string());
    row.insert("fallback_kinds".into(), fallback_kinds.join("; "));

    let fired: Vec<String> = rationale["fired"]
        .as_array()
        .map(|fired| {
            fired
                .iter()
                .map(|hazard| {
                    format!(
                        "{}:{}:{}",
                        hazard["question"].as_str().unwrap_or(""),
                        hazard["probability"].as_f64().unwrap_or_default(),
                        hazard["action"].as_str().unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    row.insert("fired_hazards".into(), fired.join("; "));

    row.insert("task".into(), record.task.clone().unwrap_or_default());
    let facts = &record.precomputed;
    row.insert("files_changed".into(), facts.files_changed.to_string());
    row.insert("files_added".into(), facts.files_added.to_string());
    row.insert("files_deleted".into(), facts.files_deleted.to_string());
    row.insert(
        "max_shrink_ratio".into(),
        format!("{:.4}", facts.max_shrink_ratio),
    );
    row.insert(
        "sensitive_path_count".into(),
        facts.sensitive_paths.len().to_string(),
    );
    row.insert("sensitive_paths".into(), facts.sensitive_paths.join("; "));
    row.insert(
        "any_diff_truncated".into(),
        facts.any_diff_truncated.to_string(),
    );

    let diff = concat_diffs(&record.changes).unwrap_or_default();
    row.insert("diff_bytes".into(), diff.len().to_string());
    row.insert("diff_sha256".into(), hex(&sha256(diff.as_bytes())));
    if options.include_diffs {
        row.insert(DIFF_COLUMN.into(), diff);
    }

    // Per-question answers. A question the assessors could not answer leaves
    // empty cells rather than zeros — "not evaluated" and "evaluated as zero"
    // are different facts, and a training script that conflated them would
    // learn from a lie.
    for question in &battery.questions {
        let prefix = format!("q_{}", question.id);
        let answer = &rationale["answers"][&question.id];
        let missing = answer.is_null();
        let get = |field: &str| -> String {
            if missing {
                String::new()
            } else {
                answer[field]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        answer[field]
                            .as_f64()
                            .map(|value| format!("{value:.6}"))
                            .unwrap_or_default()
                    })
            }
        };

        match &question.kind {
            crate::question::QuestionKind::Boolean => {
                row.insert(format!("{prefix}_p"), get("probability"));
            }
            crate::question::QuestionKind::Rubric { .. } => {
                row.insert(format!("{prefix}_level"), get("level"));
            }
            crate::question::QuestionKind::Category { .. } => {
                row.insert(format!("{prefix}_category"), get("category"));
            }
        }
        row.insert(format!("{prefix}_confidence"), get("confidence"));
        row.insert(
            format!("{prefix}_calibration"),
            if missing {
                String::new()
            } else {
                answer["calibration"]["kind"]
                    .as_str()
                    .unwrap_or("")
                    .to_string()
            },
        );
    }

    row
}

/// Digest over the canonical serialisation of a row's fields.
fn row_digest(row: &Fields) -> String {
    let canonical = serde_json::to_string(row).unwrap_or_default();
    hex(&sha256(canonical.as_bytes()))
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/* ------------------------------ laya training ---------------------------- */

/// One training case in the format Laya's fine-tuning loop consumes.
///
/// Laya is trained with a proper-scoring-rule reward against a **full
/// distribution** per question, not an argmax label — see
/// `build_training_item` in the official notebook, where the target is
/// `[gold["probabilities"][k] for k in keys]`. That is why the assessor keeps
/// `Answer::distribution` instead of only the winning option: dropping it here
/// would make the corpus unusable for exactly the thing it is collected for.
#[derive(Debug, Clone, Serialize)]
pub struct LayaCase {
    pub id: String,
    /// The state as it was sent to the assessor.
    pub state: crate::state::ChangeSetState,
    /// The battery, in the same wire shape the request used.
    pub questions: serde_json::Value,
    /// `{question_id: {"probabilities": {label: p}}}`.
    pub gold: serde_json::Value,
    /// Provenance, ignored by the trainer but useful when the corpus is audited
    /// or split.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<LayaMeta>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayaMeta {
    pub session_id: String,
    pub review_id: u64,
    pub battery_fingerprint: String,
    pub model: Option<String>,
    pub human_outcome: Option<String>,
    /// Whether the human agreed with the model's decision. A distillation run
    /// wants this to filter; a calibration run wants it as the label.
    pub human_agreed: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct LayaExportOptions {
    /// Keep only cases a person resolved.
    pub resolved_only: bool,
    /// Keep only cases where the human agreed with the model. Distilling a
    /// disagreement teaches the model to reproduce a decision that was
    /// rejected.
    pub agreed_only: bool,
    /// Drop answers whose calibration is not trustworthy, rather than shipping
    /// an uncalibrated number as if it were a target.
    pub trustworthy_only: bool,
}

impl Default for LayaExportOptions {
    fn default() -> Self {
        Self {
            resolved_only: false,
            agreed_only: false,
            trustworthy_only: true,
        }
    }
}

/// Build one case per review, or `None` when the review has nothing usable.
pub fn laya_case(
    session_id: &str,
    record: &ReviewRecord,
    resolution: Option<&ResolutionRecord>,
    options: &LayaExportOptions,
) -> Option<LayaCase> {
    if options.resolved_only && resolution.is_none() {
        return None;
    }

    let battery = battery::change_set();
    let rationale = &record.decision["rationale"];
    let assessed = &record.assessed_action;

    let human_outcome = resolution.map(|r| r.human_outcome.clone());
    let human_agreed = human_outcome.as_ref().map(|outcome| {
        let human_applied = outcome == "apply";
        let model_applied = assessed == "auto_apply";
        human_applied == model_applied
    });

    if options.agreed_only && human_agreed != Some(true) {
        return None;
    }

    let mut questions = serde_json::Map::new();
    let mut gold = serde_json::Map::new();

    for question in &battery.questions {
        let answer = &rationale["answers"][&question.id];
        if answer.is_null() {
            continue;
        }
        // An untrustworthy number is not a target. Including it would teach the
        // model to reproduce an answer the router itself refuses to act on.
        let calibration = answer["calibration"]["kind"].as_str().unwrap_or("");
        if options.trustworthy_only && calibration == "uncalibrated" {
            continue;
        }

        let labels: Vec<String> = match &question.kind {
            crate::question::QuestionKind::Boolean => {
                vec!["false".to_string(), "true".to_string()]
            }
            crate::question::QuestionKind::Rubric { levels } => {
                (0..levels.len()).map(|index| index.to_string()).collect()
            }
            crate::question::QuestionKind::Category { options } => options.clone(),
        };

        let values: Vec<f64> = match answer["distribution"].as_array() {
            Some(distribution) => distribution
                .iter()
                .filter_map(serde_json::Value::as_f64)
                .collect(),
            // An `Exact` answer — everything the rules pass produces — is a
            // point mass with no distribution attached. Materialising it here
            // rather than dropping it matters: those are the only *free, exact*
            // labels in the corpus, produced at any scale with no model and no
            // human. Throwing them away would leave only distilled ones.
            None if calibration == "exact" => match point_mass(&question.kind, answer) {
                Some(mass) => mass,
                None => continue,
            },
            None => continue,
        };
        if values.len() != labels.len() {
            continue;
        }

        questions.insert(question.id.clone(), question_to_wire(question));
        gold.insert(
            question.id.clone(),
            serde_json::json!({
                "probabilities": labels
                    .iter()
                    .cloned()
                    .zip(values)
                    .collect::<BTreeMap<String, f64>>(),
            }),
        );
    }

    if gold.is_empty() {
        return None;
    }

    Some(LayaCase {
        id: format!("{session_id}#{}", record.review_id),
        state: crate::state::ChangeSetState {
            task: record.task.clone(),
            changes: record.changes.clone(),
            precomputed: record.precomputed.clone(),
        },
        questions: serde_json::Value::Object(questions),
        gold: serde_json::Value::Object(gold),
        meta: Some(LayaMeta {
            session_id: session_id.to_string(),
            review_id: record.review_id,
            battery_fingerprint: record.battery_fingerprint.clone(),
            model: rationale["model"].as_str().map(str::to_string),
            human_outcome,
            human_agreed,
        }),
    })
}

/// Turn an exact answer into the point mass it represents.
fn point_mass(
    kind: &crate::question::QuestionKind,
    answer: &serde_json::Value,
) -> Option<Vec<f64>> {
    match kind {
        crate::question::QuestionKind::Boolean => {
            let yes = answer["probability"].as_f64()?;
            Some(vec![1.0 - yes, yes])
        }
        crate::question::QuestionKind::Rubric { levels } => {
            if levels.is_empty() {
                return None;
            }
            let level = answer["level"].as_f64()?;
            let mut mass = vec![0.0; levels.len()];
            let index = (level * (levels.len() - 1) as f64).round() as usize;
            *mass.get_mut(index.min(levels.len() - 1))? = 1.0;
            Some(mass)
        }
        crate::question::QuestionKind::Category { options } => {
            let chosen = answer["category"].as_str()?;
            let mut mass = vec![0.0; options.len()];
            let index = options.iter().position(|option| option == chosen)?;
            *mass.get_mut(index)? = 1.0;
            Some(mass)
        }
    }
}

/// A question in the same wire shape the request used, so the corpus and the
/// live request cannot drift apart.
fn question_to_wire(question: &crate::question::Question) -> serde_json::Value {
    match &question.kind {
        crate::question::QuestionKind::Boolean => serde_json::json!({
            "type": "noul",
            "instructions": question.instructions,
        }),
        crate::question::QuestionKind::Rubric { levels } => serde_json::json!({
            "type": "score",
            "instructions": question.instructions,
            "criteria": levels,
        }),
        crate::question::QuestionKind::Category { options } => serde_json::json!({
            "type": "choice",
            "instructions": question.instructions,
            "criteria": options
                .iter()
                .map(|option| (option.clone(), serde_json::Value::Null))
                .collect::<serde_json::Map<String, serde_json::Value>>(),
        }),
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayaExportReport {
    pub jsonl: String,
    pub cases: usize,
    pub skipped: usize,
    pub questions: usize,
}

/// Export every usable review as one JSONL line in Laya's training format.
pub fn export_laya(sessions: &[SessionLog], options: &LayaExportOptions) -> LayaExportReport {
    let mut lines = Vec::new();
    let mut skipped = 0usize;
    let mut questions = 0usize;

    for session in sessions {
        let resolutions: BTreeMap<u64, &ResolutionRecord> = session
            .entries
            .iter()
            .filter_map(|entry| match entry {
                LogEntry::Resolution(resolution) => Some((resolution.review_id, resolution)),
                LogEntry::Review(_) => None,
            })
            .collect();

        let mut reviews: Vec<&ReviewRecord> = session
            .entries
            .iter()
            .filter_map(|entry| match entry {
                LogEntry::Review(record) => Some(record.as_ref()),
                LogEntry::Resolution(_) => None,
            })
            .collect();
        reviews.sort_by_key(|record| (record.at_ms, record.review_id));

        for record in reviews {
            match laya_case(
                &session.session_id,
                record,
                resolutions.get(&record.review_id).copied(),
                options,
            ) {
                Some(case) => {
                    questions += case.gold.as_object().map(|g| g.len()).unwrap_or(0);
                    match serde_json::to_string(&case) {
                        Ok(line) => lines.push(line),
                        Err(_) => skipped += 1,
                    }
                }
                None => skipped += 1,
            }
        }
    }

    LayaExportReport {
        cases: lines.len(),
        skipped,
        questions,
        jsonl: if lines.is_empty() {
            String::new()
        } else {
            lines.join("\n") + "\n"
        },
    }
}

/* ---------------------------------- csv ---------------------------------- */

/// RFC 4180 field encoding. A diff contains commas, quotes and newlines, so
/// this is not optional.
fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Parse a CSV row into fields, honouring quoted sections.
fn parse_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if quoted => {
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            }
            '"' if current.is_empty() => quoted = true,
            ',' if !quoted => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}

/* --------------------------------- verify -------------------------------- */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub rows: usize,
    pub head: String,
    /// 1-based row numbers whose digest did not match.
    pub broken: Vec<usize>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.broken.is_empty()
    }
}

/// Recompute the chain and report the first rows that do not match.
pub fn verify_csv(text: &str) -> Result<VerifyReport, String> {
    let mut lines = text.lines();
    let header = lines.next().ok_or_else(|| "empty CSV".to_string())?;
    let columns: Vec<&str> = header.split(',').collect();

    let index_of = |name: &str| -> Result<usize, String> {
        columns
            .iter()
            .position(|column| *column == name)
            .ok_or_else(|| format!("missing column `{name}`"))
    };
    let row_hash_at = index_of("row_hash")?;
    let prev_at = index_of("prev_row_hash")?;

    let mut previous = "0".repeat(64);
    let mut broken = Vec::new();
    let mut count = 0usize;

    // Diffs contain newlines, so the file cannot be split naively on `\n`.
    for record in split_csv_records(lines.collect::<Vec<_>>().join("\n").as_str()) {
        if record.trim().is_empty() {
            continue;
        }
        count += 1;
        let values = parse_csv_row(&record);
        if values.len() != columns.len() {
            broken.push(count);
            continue;
        }

        let mut fields = Fields::new();
        for (column, value) in columns.iter().zip(&values) {
            fields.insert((*column).to_string(), value.clone());
        }

        let recorded_prev = fields.get("prev_row_hash").cloned().unwrap_or_default();
        let recorded_hash = fields.get("row_hash").cloned().unwrap_or_default();
        if recorded_prev != previous {
            broken.push(count);
        }

        // The digest covers the row without its own hash.
        fields.remove("row_hash");
        let recomputed = row_digest(&fields);
        if recomputed != recorded_hash {
            broken.push(count);
        }

        previous = recorded_hash;
        let _ = (row_hash_at, prev_at);
    }

    Ok(VerifyReport {
        rows: count,
        head: previous,
        broken,
    })
}

/// Split CSV text into records, respecting quoted newlines.
fn split_csv_records(text: &str) -> Vec<String> {
    let mut records = Vec::new();
    let mut current = String::new();
    let mut quoted = false;

    for c in text.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            '\n' if !quoted => {
                records.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        records.push(current);
    }
    records
}

/// Columns present in an exported CSV, for a caller that wants to check the
/// schema before loading it.
pub fn columns_of(text: &str) -> BTreeSet<String> {
    text.lines()
        .next()
        .map(|header| header.split(',').map(str::to_string).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review(id: u64, action: &str, at: u64) -> LogEntry {
        LogEntry::Review(Box::new(ReviewRecord {
            review_id: id,
            at_ms: at,
            mode: "hosted".into(),
            shadow: true,
            task: Some("fix a bug".into()),
            call: Some(format!("call-{id}")),
            decision: serde_json::json!({
                "action": action,
                "rationale": {
                    "summary": "s",
                    "assessor": "rules",
                    "model": "jev-1.13.0",
                    "fired": [],
                    "hardRules": [],
                    "fallbacks": [],
                    "answers": {
                        "lost_content": {
                            "probability": 0.1,
                            "calibration": { "kind": "calibrated" }
                        }
                    }
                }
            }),
            assessed_action: action.into(),
            battery_fingerprint: battery::change_set().fingerprint(),
            policy: serde_json::json!({}),
            ledger_head: Some("abc".into()),
            precomputed: PrecomputedFacts {
                files_changed: 1,
                ..Default::default()
            },
            changes: vec![crate::state::ChangeSummary {
                path: "a.py".into(),
                op: wsbox::protocol::Op::Modify,
                before_bytes: Some(1),
                after_bytes: Some(1),
                diff: Some("@@ -1 +1 @@\n-a\n+b\n".into()),
            }],
        }))
    }

    fn sessions() -> Vec<SessionLog> {
        vec![SessionLog {
            session_id: "s1".into(),
            entries: vec![
                review(1, "auto_apply", 100),
                LogEntry::Resolution(ResolutionRecord {
                    review_id: 1,
                    at_ms: 200,
                    human_outcome: "apply".into(),
                    note: Some("fine, and it had a comma, a \"quote\" and\na newline".into()),
                }),
                review(2, "hold", 300),
            ],
        }]
    }

    #[test]
    fn export_produces_a_header_and_one_row_per_review() {
        let report = export(&sessions(), &ExportOptions::default()).expect("export");
        assert_eq!(report.rows, 2);
        assert_eq!(report.resolved, 1);
        assert!(report.csv.starts_with("row_index,"));
    }

    #[test]
    fn the_chain_verifies() {
        let report = export(&sessions(), &ExportOptions::default()).expect("export");
        let verified = verify_csv(&report.csv).expect("verify");
        assert!(verified.ok(), "{:?}", verified.broken);
        assert_eq!(verified.rows, 2);
        assert_eq!(verified.head, report.head);
    }

    #[test]
    fn editing_a_cell_breaks_the_chain() {
        let report = export(&sessions(), &ExportOptions::default()).expect("export");
        let tampered = report.csv.replace("auto_apply", "review");
        let verified = verify_csv(&tampered).expect("verify");
        assert!(
            !verified.ok(),
            "a hand-edited CSV must not verify — this is what makes it auditable"
        );
    }

    #[test]
    fn the_human_outcome_is_carried_through() {
        let report = export(&sessions(), &ExportOptions::default()).expect("export");
        assert!(report.csv.contains(",apply,"));
        assert!(report.csv.contains("resolved_at_ms"));
    }

    /// The label weakness, made visible: the model's answer and the person's
    /// verdict are separate columns, so a consumer can tell which it is using.
    #[test]
    fn model_answers_and_human_labels_are_separate_columns() {
        let report = export(&sessions(), &ExportOptions::default()).expect("export");
        let header = report.csv.lines().next().unwrap();
        assert!(header.contains("q_lost_content_p"));
        assert!(header.contains("human_outcome"));
    }

    #[test]
    fn unanswered_questions_are_empty_not_zero() {
        let report = export(&sessions(), &ExportOptions::default()).expect("export");
        let header: Vec<&str> = report.csv.lines().next().unwrap().split(',').collect();
        let index = header
            .iter()
            .position(|c| *c == "q_beyond_task_p")
            .expect("column");
        let row = split_csv_records(&report.csv).into_iter().nth(1).unwrap();
        let fields = parse_csv_row(&row);
        assert_eq!(
            fields[index], "",
            "an unanswered question must not look like a zero"
        );
    }

    #[test]
    fn diffs_are_quoted_so_commas_and_newlines_survive() {
        let options = ExportOptions {
            include_diffs: true,
        };
        let report = export(&sessions(), &options).expect("export");
        let verified = verify_csv(&report.csv).expect("verify");
        assert!(verified.ok(), "{:?}", verified.broken);
        assert!(report.csv.contains("### file:") || report.csv.contains("@@ -1 +1 @@"));
    }

    #[test]
    fn the_diff_can_be_left_out_for_a_compact_table() {
        let report = export(&sessions(), &ExportOptions::default()).expect("export");
        assert!(!columns_of(&report.csv).contains("diff"));
        assert!(columns_of(&report.csv).contains("diff_sha256"));
    }

    #[test]
    fn csv_field_quotes_only_when_needed() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("two\nlines"), "\"two\nlines\"");
    }

    /* ----------------------------- laya export --------------------------- */

    fn with_answers(mut record: ReviewRecord, answers: serde_json::Value) -> ReviewRecord {
        record.decision["rationale"]["answers"] = answers;
        record
    }

    fn answer(
        value: serde_json::Value,
        calibration: &str,
        distribution: Option<Vec<f64>>,
    ) -> serde_json::Value {
        let mut object = value.as_object().cloned().unwrap_or_default();
        object.insert(
            "calibration".into(),
            serde_json::json!({ "kind": calibration }),
        );
        if let Some(distribution) = distribution {
            object.insert("distribution".into(), serde_json::json!(distribution));
        }
        serde_json::Value::Object(object)
    }

    fn laya_session(answers: serde_json::Value) -> Vec<SessionLog> {
        let LogEntry::Review(record) = review(1, "auto_apply", 100) else {
            unreachable!()
        };
        vec![SessionLog {
            session_id: "s1".into(),
            entries: vec![LogEntry::Review(Box::new(with_answers(*record, answers)))],
        }]
    }

    #[test]
    fn laya_export_emits_one_case_with_distributions() {
        let answers = serde_json::json!({
            "lost_content": answer(
                serde_json::json!({"probability": 0.2}),
                "calibrated",
                Some(vec![0.8, 0.2]),
            ),
            "category": answer(
                serde_json::json!({"category": "fix"}),
                "calibrated",
                Some(vec![0.1, 0.2, 0.3, 0.4, 0.0, 0.0]),
            ),
        });
        let report = export_laya(&laya_session(answers), &LayaExportOptions::default());
        assert_eq!(report.cases, 1);
        assert_eq!(report.questions, 2);

        let case: serde_json::Value = serde_json::from_str(report.jsonl.trim()).expect("json");
        assert_eq!(case["gold"]["lost_content"]["probabilities"]["true"], 0.2);
        assert_eq!(case["gold"]["lost_content"]["probabilities"]["false"], 0.8);
    }

    /// The official training loop reads the target as
    /// `[gold["probabilities"][k] for k in keys]`, where `keys` comes from the
    /// question's own criteria. If the two ever disagree the corpus silently
    /// trains on misaligned labels, so the alignment is asserted rather than
    /// assumed.
    #[test]
    fn laya_label_keys_match_the_question_criteria() {
        let answers = serde_json::json!({
            "lost_content": answer(
                serde_json::json!({"probability": 0.2}), "calibrated", Some(vec![0.8, 0.2])),
            "severity": answer(
                serde_json::json!({"level": 0.5}), "calibrated", Some(vec![0.1, 0.2, 0.3, 0.4])),
            "category": answer(
                serde_json::json!({"category": "fix"}), "calibrated",
                Some(vec![0.1, 0.2, 0.3, 0.4, 0.0, 0.0])),
        });
        let report = export_laya(&laya_session(answers), &LayaExportOptions::default());
        let case: serde_json::Value = serde_json::from_str(report.jsonl.trim()).expect("json");

        for (id, gold) in case["gold"].as_object().expect("gold") {
            let question = &case["questions"][id];
            let probabilities = gold["probabilities"].as_object().expect("probs");
            let expected: Vec<String> = match question["type"].as_str().expect("type") {
                "noul" => vec!["false".into(), "true".into()],
                "score" => (0..question["criteria"].as_array().unwrap().len())
                    .map(|i| i.to_string())
                    .collect(),
                _ => question["criteria"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect(),
            };
            let mut got: Vec<String> = probabilities.keys().cloned().collect();
            got.sort();
            let mut expected = expected;
            expected.sort();
            assert_eq!(got, expected, "label keys drifted for `{id}`");
        }
    }

    /// Everything the rules pass produces is a point mass with no distribution
    /// attached. Those are the only free, exact labels in the corpus, so they
    /// must be materialised rather than dropped.
    #[test]
    fn exact_answers_become_point_masses() {
        let answers = serde_json::json!({
            "lost_content": answer(serde_json::json!({"probability": 0.0}), "exact", None),
            "leftover_debug": answer(serde_json::json!({"probability": 1.0}), "exact", None),
            "category": answer(serde_json::json!({"category": "formatting"}), "exact", None),
        });
        let report = export_laya(&laya_session(answers), &LayaExportOptions::default());
        let case: serde_json::Value = serde_json::from_str(report.jsonl.trim()).expect("json");

        assert_eq!(case["gold"]["lost_content"]["probabilities"]["false"], 1.0);
        assert_eq!(case["gold"]["leftover_debug"]["probabilities"]["true"], 1.0);
        assert_eq!(case["gold"]["category"]["probabilities"]["formatting"], 1.0);
    }

    #[test]
    fn uncalibrated_answers_are_excluded_by_default() {
        let answers = serde_json::json!({
            "lost_content": answer(
                serde_json::json!({"probability": 0.2}), "uncalibrated", Some(vec![0.8, 0.2])),
        });
        let report = export_laya(&laya_session(answers), &LayaExportOptions::default());
        assert_eq!(report.cases, 0, "an uncalibrated number is not a target");

        let included = export_laya(
            &laya_session(serde_json::json!({
                "lost_content": answer(
                    serde_json::json!({"probability": 0.2}), "uncalibrated", Some(vec![0.8, 0.2])),
            })),
            &LayaExportOptions {
                trustworthy_only: false,
                ..LayaExportOptions::default()
            },
        );
        assert_eq!(included.cases, 1);
    }

    #[test]
    fn agreed_only_drops_disagreements() {
        let answers = serde_json::json!({
            "lost_content": answer(
                serde_json::json!({"probability": 0.1}), "calibrated", Some(vec![0.9, 0.1])),
        });
        // The model said auto_apply; the person rejected.
        let mut sessions = laya_session(answers);
        sessions[0]
            .entries
            .push(LogEntry::Resolution(ResolutionRecord {
                review_id: 1,
                at_ms: 200,
                human_outcome: "reject".into(),
                note: None,
            }));

        let all = export_laya(&sessions, &LayaExportOptions::default());
        assert_eq!(all.cases, 1);

        let agreed = export_laya(
            &sessions,
            &LayaExportOptions {
                agreed_only: true,
                ..LayaExportOptions::default()
            },
        );
        assert_eq!(
            agreed.cases, 0,
            "training on a disagreement teaches the model to reproduce a rejected decision"
        );
    }

    #[test]
    fn laya_export_carries_provenance() {
        let answers = serde_json::json!({
            "lost_content": answer(
                serde_json::json!({"probability": 0.1}), "calibrated", Some(vec![0.9, 0.1])),
        });
        let report = export_laya(&laya_session(answers), &LayaExportOptions::default());
        let case: serde_json::Value = serde_json::from_str(report.jsonl.trim()).expect("json");
        assert_eq!(case["meta"]["sessionId"], "s1");
        assert_eq!(case["meta"]["reviewId"], 1);
        assert!(
            case["meta"]["batteryFingerprint"].is_string(),
            "a corpus that cannot be tied to a battery version is not reusable"
        );
    }
}
