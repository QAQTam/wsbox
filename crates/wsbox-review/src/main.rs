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

    /// Export the review history as an auditable CSV.
    Export(ExportArgs),

    /// Check an exported CSV's row chain.
    Verify(VerifyArgs),
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

    /// Whether a person clicked or the decision window expired.
    ///
    /// A timeout is not a label. Record it honestly or the corpus will teach
    /// the model that silence means consent.
    #[arg(long, value_enum, default_value_t = SourceArg::Explicit)]
    source: SourceArg,

    /// How long the decision window was open, in milliseconds.
    #[arg(long)]
    window_ms: Option<u64>,

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

#[derive(clap::Args)]
struct ExportArgs {
    /// A single session, or `--all` for every session in the ledger directory.
    #[arg(long)]
    session: Option<String>,

    #[arg(long, conflicts_with = "session")]
    all: bool,

    #[arg(long)]
    ledger_dir: Option<PathBuf>,

    /// Write here instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Embed the diffs. Off gives a compact audit-only table.
    #[arg(long)]
    include_diffs: bool,

    /// `csv` for the auditable table, `laya` for a fine-tuning corpus.
    #[arg(long, value_enum, default_value_t = FormatArg::Csv)]
    format: FormatArg,

    /// laya: keep only reviews a person resolved.
    #[arg(long)]
    resolved_only: bool,

    /// laya: keep only reviews where the person agreed with the model. Training
    /// on disagreements teaches the model to reproduce a rejected decision.
    #[arg(long)]
    agreed_only: bool,

    /// laya: keep only reviews a person actually clicked. Windows that simply
    /// expired are not labels.
    #[arg(long)]
    observed_only: bool,

    /// laya: include answers the router refuses to threshold. Off by default —
    /// an uncalibrated number is not a target.
    #[arg(long)]
    include_uncalibrated: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FormatArg {
    /// Auditable table with a tamper-evident row chain.
    Csv,
    /// One JSON object per case, in the shape Laya's fine-tuning loop reads.
    Laya,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// The CSV to check, or `-` for stdin.
    #[arg(long, default_value = "-")]
    input: String,

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SourceArg {
    /// A person clicked.
    Explicit,
    /// The window expired and the model's choice was taken.
    Timeout,
}

impl From<SourceArg> for wsbox_review::export::HumanSource {
    fn from(value: SourceArg) -> Self {
        match value {
            SourceArg::Explicit => Self::Explicit,
            SourceArg::Timeout => Self::Timeout,
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
        Command::Export(args) => run_export(args),
        Command::Verify(args) => run_verify(args),
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

/// How many *clicked* decisions a risk class needs before its gate is relaxed.
///
/// Deliberately counted in observed decisions, not total ones. A gate that
/// relaxes because a machine sat unattended for a week has measured nothing.
const MIN_OBSERVED_FOR_PROMOTION: u64 = 30;

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
        "source": wsbox_review::export::HumanSource::from(args.source),
        "windowMs": args.window_ms,
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

    // `(outcome, was it clicked)` — the second half is what decides whether a
    // resolution counts as evidence.
    let resolutions: std::collections::BTreeMap<u64, (String, bool)> = records
        .iter()
        .filter(|record| record["kind"] == "resolution")
        .filter_map(|record| {
            let source = record["source"].as_str().unwrap_or("explicit");
            Some((
                record["reviewId"].as_u64()?,
                (
                    record["humanOutcome"].as_str()?.to_string(),
                    source == "explicit",
                ),
            ))
        })
        .collect();

    let mut observed: u64 = 0;
    let mut timed_out: u64 = 0;

    for record in records.iter().filter(|record| record["kind"] == "review") {
        let Some(id) = record["reviewId"].as_u64() else {
            continue;
        };
        let bucket = match record["decision"]["action"].as_str().unwrap_or("review") {
            "auto_apply" => &mut auto,
            "hold" => &mut hold,
            _ => &mut review,
        };
        match resolutions.get(&id) {
            Some((outcome, true)) => {
                observed += 1;
                if outcome == "apply" {
                    bucket.applied += 1;
                } else {
                    bucket.rejected += 1;
                }
            }
            Some((_, false)) => {
                // A window that expired is not a verdict. Counting it as one
                // would let a machine left alone overnight look like a user who
                // approved everything.
                timed_out += 1;
                bucket.unresolved += 1;
            }
            None => bucket.unresolved += 1,
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
            "observed": observed,
            "timedOut": timed_out,
            "withFallbacks": with_fallbacks,
            "buckets": {
                "auto_apply": { "applied": auto.applied, "rejected": auto.rejected, "unresolved": auto.unresolved },
                "review":     { "applied": review.applied, "rejected": review.rejected, "unresolved": review.unresolved },
                "hold":       { "applied": hold.applied, "rejected": hold.rejected, "unresolved": hold.unresolved },
            },
            "dangerousAutoApprove": auto.rejected,
            "annoyingHold": hold.applied,
            "readyToPromote": auto.rejected == 0 && observed >= MIN_OBSERVED_FOR_PROMOTION,
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

    println!(
        "reviews {total}   observed {observed}   timed out {timed_out}   with fallbacks {with_fallbacks}"
    );
    println!(
        "only the {observed} observed one(s) are evidence; a countdown that expired is the absence of one.\n"
    );
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
        println!("           do not relax the gate until this is zero.");
    } else if observed == 0 {
        println!("no observed decisions yet — a timeout is not evidence for promotion.");
    } else if observed < MIN_OBSERVED_FOR_PROMOTION {
        println!(
            "no dangerous auto-approvals in {observed} observed review(s), but {MIN_OBSERVED_FOR_PROMOTION} are needed before relaxing the gate."
        );
    } else {
        println!(
            "no dangerous auto-approvals in {observed} observed review(s) — the gate can be relaxed for the classes with zero."
        );
    }
    if hold.applied > 0 {
        println!(
            "NOISY: {} change set(s) were held but applied anyway — thresholds may be too tight.",
            hold.applied
        );
    }
    Ok(())
}

/* --------------------------------- export -------------------------------- */

fn ledger_dir_of(args: &Option<PathBuf>) -> PathBuf {
    args.clone()
        .unwrap_or_else(wsbox::session::default_ledger_dir)
}

/// Every session directory under the ledger root.
fn all_sessions(dir: &std::path::Path) -> Result<Vec<String>, String> {
    let sessions = dir.join("sessions");
    let entries = std::fs::read_dir(&sessions)
        .map_err(|error| format!("cannot list {}: {error}", sessions.display()))?;
    let mut ids: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    ids.sort();
    Ok(ids)
}

fn collect_logs(args: &ExportArgs) -> Result<Vec<wsbox_review::export::SessionLog>, String> {
    let dir = ledger_dir_of(&args.ledger_dir);
    let ids: Vec<String> = match (&args.session, args.all) {
        (Some(session), _) => vec![session.clone()],
        (None, true) => all_sessions(&dir)?,
        (None, false) => {
            return Err("pass --session <id> or --all".into());
        }
    };

    let mut logs = Vec::new();
    for id in ids {
        let session = load_session(&id, Some(&dir))?;
        let text = match std::fs::read_to_string(review_log(&session)) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot read review log for {id}: {error}")),
        };
        let entries = wsbox_review::export::LogEntry::parse(&text)
            .map_err(|error| format!("{id}: {error}"))?;
        logs.push(wsbox_review::export::SessionLog {
            session_id: id,
            entries,
        });
    }
    Ok(logs)
}

fn run_export(args: &ExportArgs) -> Result<(), String> {
    use std::io::Write;

    let logs = collect_logs(args)?;

    match args.format {
        FormatArg::Csv => {
            let options = wsbox_review::export::ExportOptions {
                include_diffs: args.include_diffs,
            };
            let report = wsbox_review::export::export(&logs, &options)?;
            match &args.out {
                Some(path) => {
                    std::fs::write(path, &report.csv)
                        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
                    eprintln!(
                        "{} row(s), {} resolved ({} observed), {} session(s) -> {}",
                        report.rows,
                        report.resolved,
                        report.observed,
                        logs.len(),
                        path.display()
                    );
                    eprintln!("chain head: {}", report.head);
                }
                None => {
                    let stdout = std::io::stdout();
                    stdout
                        .lock()
                        .write_all(report.csv.as_bytes())
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        FormatArg::Laya => {
            let options = wsbox_review::export::LayaExportOptions {
                resolved_only: args.resolved_only,
                observed_only: args.observed_only,
                agreed_only: args.agreed_only,
                trustworthy_only: !args.include_uncalibrated,
            };
            let report = wsbox_review::export::export_laya(&logs, &options);
            match &args.out {
                Some(path) => {
                    std::fs::write(path, &report.jsonl)
                        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
                    eprintln!(
                        "{} case(s), {} question(s), {} skipped -> {}",
                        report.cases,
                        report.questions,
                        report.skipped,
                        path.display()
                    );
                }
                None => {
                    let stdout = std::io::stdout();
                    stdout
                        .lock()
                        .write_all(report.jsonl.as_bytes())
                        .map_err(|error| error.to_string())?;
                }
            }
        }
    }
    Ok(())
}

fn run_verify(args: &VerifyArgs) -> Result<(), String> {
    let text = if args.input == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|error| error.to_string())?;
        buffer
    } else {
        std::fs::read_to_string(&args.input)
            .map_err(|error| format!("cannot read {}: {error}", args.input))?
    };

    let report = wsbox_review::export::verify_csv(&text)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else if report.ok() {
        println!(
            "{} row(s) verified, chain head {}",
            report.rows, report.head
        );
    } else {
        println!(
            "{} row(s) checked, {} broken",
            report.rows,
            report.broken.len()
        );
        println!("broken rows: {:?}", report.broken);
    }

    if !report.ok() {
        return Err("the CSV chain does not verify".into());
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
    use wsbox_review::export::{LogEntry, ReviewRecord};

    let path = review_log(session);
    let existing = read_log(session)?;
    let review_id = existing
        .iter()
        .filter(|record| record["kind"] == "review")
        .filter_map(|record| record["reviewId"].as_u64())
        .max()
        .unwrap_or(0)
        + 1;

    let record = ReviewRecord {
        review_id,
        at_ms: wsbox::ledger::now_ms(),
        mode: mode_name(outcome.mode).to_string(),
        shadow: outcome.shadow,
        task: args.task.clone(),
        call: args.call.clone(),
        decision: serde_json::to_value(&outcome.decision).map_err(|error| error.to_string())?,
        assessed_action: action_name(outcome.assessed_action()).to_string(),
        battery_fingerprint: outcome.battery.fingerprint(),
        // Recorded so the decision can be replayed. Without it, "why was this
        // auto-approved?" has no answer.
        policy: serde_json::to_value(&policy_of(args)?).map_err(|error| error.to_string())?,
        ledger_head: session.ledger_head().ok(),
        precomputed: outcome.state.precomputed.clone(),
        changes: outcome.state.changes.clone(),
    };

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let line = serde_json::to_string(&LogEntry::Review(Box::new(record)))
        .map_err(|error| error.to_string())?;
    writeln!(file, "{line}")
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    eprintln!("recorded review {review_id}");
    Ok(())
}

fn policy_of(args: &RunArgs) -> Result<Policy, String> {
    load_policy(args.policy.as_ref())
}
