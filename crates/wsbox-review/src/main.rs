//! `wsbox-review` CLI.
//!
//! Reads a change set — from a live wsbox session or from a JSON file — and
//! prints a decision. Nothing here writes to a workspace; applying is still
//! `wsbox apply`, which is the caller's move to make.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use serde::Serialize;
use wsbox::protocol::Change;
use wsbox_review::state::ChangeSetState;
use wsbox_review::{Mode, Policy, review};

#[derive(Parser)]
#[command(
    name = "wsbox-review",
    version,
    about = "Experimental review component: may this change set be applied without a human?"
)]
struct Cli {
    /// Session to review. Mutually exclusive with `--changes`.
    #[arg(long, conflicts_with = "changes")]
    session: Option<String>,

    #[arg(long)]
    ledger_dir: Option<PathBuf>,

    /// A JSON file holding a wsbox change set (`wsbox changes --json`), or `-`
    /// for stdin.
    #[arg(long)]
    changes: Option<String>,

    /// The task the agent was given. Without it, `beyond_task` is unanswerable
    /// and the change cannot be auto-approved.
    #[arg(long)]
    task: Option<String>,

    #[arg(long, value_enum, default_value_t = ModeArg::Rules)]
    mode: ModeArg,

    /// A JSON file overriding the default policy.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Append the outcome to `<session>/review.jsonl`.
    #[arg(long)]
    record: bool,

    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArg {
    /// Deterministic rules only. Never calls a model.
    Rules,
    /// Rules, then a hosted decision model if one is configured.
    Hosted,
}

impl From<ModeArg> for Mode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Rules => Mode::RulesOnly,
            ModeArg::Hosted => Mode::Hosted,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("wsbox-review: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    let policy = load_policy(cli)?;
    let (state, session) = load_state(cli)?;
    let outcome = review(state, cli.mode.into(), &policy);

    if cli.record
        && let Some(session) = &session
    {
        record(session, cli, &outcome)?;
    }

    if cli.json {
        let report = Report::from(&outcome);
        let text = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
        println!("{text}");
    } else {
        println!("{}", outcome.decision.explain());
    }
    Ok(())
}

/// The shape written to stdout and to the review log.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report<'a> {
    decision: &'a wsbox_review::Decision,
    mode: &'a str,
    battery: &'a wsbox_review::Battery,
    /// The facts the decision was made on, so a reviewer can reconstruct it.
    precomputed: &'a wsbox_review::PrecomputedFacts,
}

impl<'a> From<&'a wsbox_review::ReviewOutcome> for Report<'a> {
    fn from(outcome: &'a wsbox_review::ReviewOutcome) -> Self {
        Self {
            decision: &outcome.decision,
            mode: match outcome.mode {
                Mode::RulesOnly => "rules_only",
                Mode::Hosted => "hosted",
            },
            battery: &outcome.battery,
            precomputed: &outcome.state.precomputed,
        }
    }
}

fn load_policy(cli: &Cli) -> Result<Policy, String> {
    match &cli.policy {
        None => Ok(Policy::default()),
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            serde_json::from_str(&text).map_err(|error| format!("invalid policy: {error}"))
        }
    }
}

type Session = wsbox::session::Session;

fn load_state(cli: &Cli) -> Result<(ChangeSetState, Option<Session>), String> {
    if let Some(path) = &cli.changes {
        let text = if path == "-" {
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|error| error.to_string())?;
            buffer
        } else {
            std::fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?
        };
        let changes = parse_changes(&text)?;
        return Ok((
            ChangeSetState::from_changes(cli.task.clone(), &changes),
            None,
        ));
    }

    let session_id = cli
        .session
        .as_ref()
        .ok_or_else(|| "pass either --session or --changes".to_string())?;
    let dir = cli
        .ledger_dir
        .clone()
        .unwrap_or_else(wsbox::session::default_ledger_dir);
    let session = Session::load(&dir, session_id).map_err(|error| error.to_string())?;
    let changes = session.changes().map_err(|error| error.to_string())?;
    Ok((
        ChangeSetState::from_changes(cli.task.clone(), &changes),
        Some(session),
    ))
}

/// Accept either `wsbox changes --json` output (`{"result":{"changes":[...]}}`)
/// or a bare array of changes.
fn parse_changes(text: &str) -> Result<Vec<Change>, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| format!("invalid JSON: {error}"))?;

    let array = value
        .get("result")
        .and_then(|result| result.get("changes"))
        .or_else(|| value.get("changes"))
        .or_else(|| value.as_array().map(|_| &value));

    match array {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|error| format!("invalid changes: {error}")),
        None => Err("no `changes` array found".into()),
    }
}

/// Append the outcome to the session's review log.
///
/// This is not decoration. Every assessment paired with what a human eventually
/// decided is a labelled example, and a few months of them is the dataset you
/// would fit a calibration map or train a local model on. Running the hosted
/// model is how you earn the right to stop needing it.
fn record(
    session: &Session,
    cli: &Cli,
    outcome: &wsbox_review::ReviewOutcome,
) -> Result<(), String> {
    use std::io::Write;

    let path = session.root.join("review.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;

    let entry = serde_json::json!({
        "atMs": wsbox::ledger::now_ms(),
        "mode": match cli.mode {
            ModeArg::Rules => "rules_only",
            ModeArg::Hosted => "hosted",
        },
        "task": cli.task,
        "decision": outcome.decision,
        "batteryFingerprint": outcome.battery.fingerprint(),
        "precomputed": outcome.state.precomputed,
    });
    let line = serde_json::to_string(&entry).map_err(|error| error.to_string())?;
    writeln!(file, "{line}").map_err(|error| format!("cannot write {}: {error}", path.display()))
}
