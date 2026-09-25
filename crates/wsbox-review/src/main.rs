//! `wsbox-review` CLI.
//!
//! Reads a change set — from a live wsbox session or from a JSON file — and
//! prints a decision. Nothing here writes to a workspace; applying is still
//! `wsbox apply`, which is the caller's move to make.
//!
//! The three subcommands are the rollout path:
//!
//! * `run --shadow` records what the model would have decided while still
//!   requiring a person;
//! * `resolve` records what the person actually decided;
//! * `stats` puts the two together. The number that matters is how often the
//!   model would have auto-approved something a person rejected.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use wsbox::protocol::Change;
use wsbox_review::state::ChangeSetState;
use wsbox_review::{Mode, Policy, ReviewOutcome, review, review_shadow};

#[derive(Parser)]
#[command(
    name = "wsbox-review",
    version,
    about = "Experimental review component: may this change set be applied without a human?"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Assess a change set and report a decision.
    Run(RunArgs),

    /// Record what a person actually decided about a review.
    Resolve(ResolveArgs),

    /// Compare model decisions against human ones.
    Stats(StatsArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Session to review. Mutually exclusive with `--changes`.
    #[arg(long, conflicts_with = "changes")]
    session: Option<String>,

    #[arg(long)]
    ledger_dir: Option<PathBuf>,

    /// Restrict the review to one tool call's changes. The cumulative set is
    /// the right input for a gate on applying, but judging a call against it
    /// means one destructive edit makes every later call look destructive.
    #[arg(long)]
    call: Option<String>,

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

    /// Record the verdict but never permit an auto-apply.
    #[arg(long)]
    shadow: bool,

    /// Append the outcome to `<session>/review.jsonl`.
    #[arg(long)]
    record: bool,

    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct ResolveArgs {
    #[arg(long)]
    session: String,

    #[arg(long)]
    ledger_dir: Option<PathBuf>,

    /// What the person did.
    #[arg(long, value_enum)]
    outcome: HumanOutcome,

    /// Which review this resolves. Defaults to the newest unresolved one.
    #[arg(long)]
    review: Option<u64>,

    #[arg(long)]
    note: Option<String>,
}

#[derive(clap::Args)]
struct StatsArgs {
    #[arg(long)]
    session: String,

    #[arg(long)]
    ledger_dir: Option<PathBuf>,

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
enum HumanOutcome {
    /// The person applied the change.
    Apply,
    /// The person threw it away.
    Reject,
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
    match &cli.command {
        Command::Run(args) => run_review(args),
        Command::Resolve(args) => run_resolve(args),
        Command::Stats(args) => run_stats(args),
    }
}

/* ---------------------------------- run --------------------------------- */

fn run_review(args: &RunArgs) -> Result<(), String> {
    let policy = load_policy(args.policy.as_ref())?;
    let (state, session) = load_state(args)?;
    let outcome = if args.shadow {
        review_shadow(state, args.mode.into(), &policy)
    } else {
        review(state, args.mode.into(), &policy)
    };

    if args.record
        && let Some(session) = &session
    {
        record(session, args, &outcome)?;
    }

    if args.json {
        let report = Report::from(&outcome);
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        if outcome.shadow {
            println!(
                "[shadow] the model would have said: {}",
                action_name(outcome.assessed_action())
            );
        }
        println!("{}", outcome.decision.explain());
        if outcome.shadow {
            println!("\na person must still decide: `wsbox-review resolve --outcome apply|reject`");
        }
    }
    Ok(())
}

/// The shape written to stdout.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report<'a> {
    decision: &'a wsbox_review::Decision,
    /// What the model said, independent of shadow mode.
    assessed_action: &'a str,
    /// Whether the caller is permitted to act on it.
    may_auto_apply: bool,
    shadow: bool,
    mode: &'a str,
    battery: &'a wsbox_review::Battery,
    precomputed: &'a wsbox_review::PrecomputedFacts,
}

impl<'a> From<&'a ReviewOutcome> for Report<'a> {
    fn from(outcome: &'a ReviewOutcome) -> Self {
        Self {
            decision: &outcome.decision,
            assessed_action: action_name(outcome.assessed_action()),
            may_auto_apply: outcome.may_auto_apply(),
            shadow: outcome.shadow,
            mode: mode_name(outcome.mode),
            battery: &outcome.battery,
            precomputed: &outcome.state.precomputed,
        }
    }
}

fn action_name(action: wsbox_review::Action) -> &'static str {
    match action {
        wsbox_review::Action::AutoApply => "auto_apply",
        wsbox_review::Action::Review => "review",
        wsbox_review::Action::Hold => "hold",
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::RulesOnly => "rules_only",
        Mode::Hosted => "hosted",
    }
}

/* ------------------------------- resolve/stats -------------------------- */

fn review_log(session: &wsbox::session::Session) -> PathBuf {
    session.root.join("review.jsonl")
}

fn load_session(
    session: &str,
    ledger_dir: Option<&std::path::Path>,
) -> Result<wsbox::session::Session, String> {
    let dir = ledger_dir
        .map(PathBuf::from)
        .unwrap_or_else(wsbox::session::default_ledger_dir);
    wsbox::session::Session::load(&dir, session).map_err(|error| error.to_string())
}

fn read_log(session: &wsbox::session::Session) -> Result<Vec<serde_json::Value>, String> {
    let path = review_log(session);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|error| format!("corrupt log line: {error}"))
        })
        .collect()
}

fn run_resolve(args: &ResolveArgs) -> Result<(), String> {
    use std::io::Write;

    let session = load_session(&args.session, args.ledger_dir.as_deref())?;
    let records = read_log(&session)?;

    let review_id = match args.review {
        Some(id) => id,
        None => {
            let resolved: Vec<u64> = records
                .iter()
                .filter(|record| record["kind"] == "resolution")
                .filter_map(|record| record["reviewId"].as_u64())
                .collect();
            records
                .iter()
                .filter(|record| record["kind"] == "review")
                .filter_map(|record| record["reviewId"].as_u64())
                .filter(|id| !resolved.contains(id))
                .max()
                .ok_or_else(|| "no unresolved review in this session".to_string())?
        }
    };

    if !records
        .iter()
        .any(|record| record["kind"] == "review" && record["reviewId"].as_u64() == Some(review_id))
    {
        return Err(format!("no review with id {review_id}"));
    }

    let entry = serde_json::json!({
        "kind": "resolution",
        "reviewId": review_id,
        "atMs": wsbox::ledger::now_ms(),
        "humanOutcome": args.outcome,
        "note": args.note,
    });

    let path = review_log(&session);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(&entry).unwrap_or_default()
    )
    .map_err(|error| format!("cannot write {}: {error}", path.display()))?;

    println!(
        "review {review_id} resolved as {outcome:?}",
        outcome = args.outcome
    );
    Ok(())
}

#[derive(Default, Clone, Copy)]
struct Bucket {
    applied: u64,
    rejected: u64,
    unresolved: u64,
}

/// The disagreement table. This is the whole reason shadow mode exists: an
/// auto-approval that is wrong is invisible until much later, so the count of
/// "the model would have applied this and a person rejected it" has to be
/// measured *before* anything depends on the model.
fn run_stats(args: &StatsArgs) -> Result<(), String> {
    let session = load_session(&args.session, args.ledger_dir.as_deref())?;
    let records = read_log(&session)?;

    let mut auto = Bucket::default();
    let mut review = Bucket::default();
    let mut hold = Bucket::default();
    let mut with_fallbacks: u64 = 0;

    let resolutions: std::collections::BTreeMap<u64, String> = records
        .iter()
        .filter(|record| record["kind"] == "resolution")
        .filter_map(|record| {
            Some((
                record["reviewId"].as_u64()?,
                record["humanOutcome"].as_str()?.to_string(),
            ))
        })
        .collect();

    for record in records.iter().filter(|record| record["kind"] == "review") {
        let Some(id) = record["reviewId"].as_u64() else {
            continue;
        };
        let bucket = match record["decision"]["action"].as_str().unwrap_or("review") {
            "auto_apply" => &mut auto,
            "hold" => &mut hold,
            _ => &mut review,
        };
        match resolutions.get(&id).map(String::as_str) {
            Some("apply") => bucket.applied += 1,
            Some("reject") => bucket.rejected += 1,
            _ => bucket.unresolved += 1,
        }
        if record["decision"]["rationale"]["fallbacks"]
            .as_array()
            .is_some_and(|list| !list.is_empty())
        {
            with_fallbacks += 1;
        }
    }

    let total: u64 = [auto, review, hold]
        .iter()
        .map(|bucket| bucket.applied + bucket.rejected + bucket.unresolved)
        .sum();
    let resolved: u64 = [auto, review, hold]
        .iter()
        .map(|bucket| bucket.applied + bucket.rejected)
        .sum();

    if args.json {
        let payload = serde_json::json!({
            "session": args.session,
            "total": total,
            "resolved": resolved,
            "withFallbacks": with_fallbacks,
            "buckets": {
                "auto_apply": { "applied": auto.applied, "rejected": auto.rejected, "unresolved": auto.unresolved },
                "review":     { "applied": review.applied, "rejected": review.rejected, "unresolved": review.unresolved },
                "hold":       { "applied": hold.applied, "rejected": hold.rejected, "unresolved": hold.unresolved },
            },
            "dangerousAutoApprove": auto.rejected,
            "annoyingHold": hold.applied,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())?
        );
        return Ok(());
    }

    if total == 0 {
        println!("no reviews recorded in this session");
        return Ok(());
    }

    println!("reviews {total}   resolved {resolved}   with fallbacks {with_fallbacks}\n");
    println!(
        "{:<16}{:>10}{:>10}{:>12}",
        "model said", "applied", "rejected", "unresolved"
    );
    for (label, bucket) in [("auto_apply", auto), ("review", review), ("hold", hold)] {
        println!(
            "{label:<16}{:>10}{:>10}{:>12}",
            bucket.applied, bucket.rejected, bucket.unresolved
        );
    }

    println!();
    if auto.rejected > 0 {
        println!(
            "DANGEROUS: the model would have auto-applied {} change set(s) a person rejected.",
            auto.rejected
        );
        println!("           do not enable auto-approve until this is zero.");
    } else if resolved > 0 {
        println!("no dangerous auto-approvals in {resolved} resolved review(s).");
    }
    if hold.applied > 0 {
        println!(
            "NOISY: {} change set(s) were held but applied anyway — thresholds may be too tight.",
            hold.applied
        );
    }
    Ok(())
}

/* --------------------------------- loading ------------------------------- */

fn load_policy(path: Option<&PathBuf>) -> Result<Policy, String> {
    match path {
        None => Ok(Policy::default()),
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            serde_json::from_str(&text).map_err(|error| format!("invalid policy: {error}"))
        }
    }
}

fn load_state(args: &RunArgs) -> Result<(ChangeSetState, Option<wsbox::session::Session>), String> {
    if let Some(path) = &args.changes {
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
            ChangeSetState::from_changes(args.task.clone(), &changes),
            None,
        ));
    }

    let session_id = args
        .session
        .as_ref()
        .ok_or_else(|| "pass either --session or --changes".to_string())?;
    let session = load_session(session_id, args.ledger_dir.as_deref())?;
    let changes = match &args.call {
        Some(call) => session
            .changes_for_call(call)
            .map_err(|error| error.to_string())?,
        None => session.changes().map_err(|error| error.to_string())?,
    };
    Ok((
        ChangeSetState::from_changes(args.task.clone(), &changes),
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
    session: &wsbox::session::Session,
    args: &RunArgs,
    outcome: &ReviewOutcome,
) -> Result<(), String> {
    use std::io::Write;

    let path = review_log(session);
    let existing = read_log(session)?;
    let review_id = existing
        .iter()
        .filter(|record| record["kind"] == "review")
        .filter_map(|record| record["reviewId"].as_u64())
        .max()
        .unwrap_or(0)
        + 1;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;

    let entry = serde_json::json!({
        "kind": "review",
        "reviewId": review_id,
        "atMs": wsbox::ledger::now_ms(),
        "mode": mode_name(outcome.mode),
        "shadow": outcome.shadow,
        "task": args.task,
        "call": args.call,
        "decision": outcome.decision,
        "assessedAction": action_name(outcome.assessed_action()),
        "batteryFingerprint": outcome.battery.fingerprint(),
        "precomputed": outcome.state.precomputed,
    });
    let line = serde_json::to_string(&entry).map_err(|error| error.to_string())?;
    writeln!(file, "{line}")
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    eprintln!("recorded review {review_id}");
    Ok(())
}
