//! `wsbox` command line front end.
//!
//! Two shapes of use:
//!
//! * human/debug — `open`, `exec`, `changes`, `apply`, ... which build the
//!   protocol envelope for you and print something readable;
//! * machine — `run` reads one NDJSON envelope and writes one NDJSON response,
//!   which is how an agent SDK drives the engine.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wsbox::protocol::{
    ApplyParams, Backend, Envelope, ExecParams, GcParams, HistoryParams, LedgerQueryParams, Mode,
    Network, PROTOCOL_VERSION, Response, RestoreParams, SessionOpenParams, SessionRef, Spec,
};

#[derive(Parser)]
#[command(
    name = "wsbox",
    version,
    about = "Workspace ledger sandbox: every write is observed, diffed and reversible"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Probe what this host can actually do (userns, overlayfs, landlock, bwrap).
    Capabilities {
        #[arg(long)]
        json: bool,
    },

    /// Start a session over a workspace.
    Open {
        #[arg(long)]
        session: String,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long, value_enum, default_value_t = ModeArg::Auto)]
        mode: ModeArg,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
    },

    /// Run a command inside the session sandbox and report what it changed.
    Exec {
        #[arg(long)]
        session: String,
        /// Tool-call id; the ledger attributes changes to it.
        #[arg(long)]
        call: String,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 120_000)]
        timeout_ms: u64,
        /// Allow network access (default is a private netns with no route).
        #[arg(long)]
        allow_network: bool,
        /// Make the workspace read-only for this call.
        #[arg(long)]
        read_only: bool,
        /// Subtree bound straight from the real filesystem, bypassing the
        /// overlay (e.g. `target`, `node_modules`). Writes there are not
        /// journaled. May be repeated; relative paths resolve against the
        /// workspace.
        #[arg(long = "passthrough", value_name = "PATH")]
        passthrough: Vec<PathBuf>,
        /// Print the raw protocol response instead of a summary.
        #[arg(long)]
        json: bool,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },

    /// Show the accumulated change set for a session.
    Changes {
        #[arg(long)]
        session: String,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },

    /// Write the session's changes onto the real workspace.
    Apply {
        #[arg(long)]
        session: String,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
        /// Overwrite files the user changed during the session.
        #[arg(long)]
        force: bool,
    },

    /// Put files back to the session baseline.
    Restore {
        #[arg(long)]
        session: String,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        path: Option<String>,
    },

    /// Drop the session record (and revert the workspace in snapshot mode).
    Discard {
        #[arg(long)]
        session: String,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
    },

    /// Verify the ledger hash chain.
    Verify {
        #[arg(long)]
        session: String,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
    },

    /// Query the audit ledger.
    Query {
        #[arg(long)]
        session: String,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
        /// Only entries attributed to this tool-call id.
        #[arg(long)]
        call: Option<String>,
        /// Only entries that touched this path.
        #[arg(long)]
        path: Option<String>,
        /// Only entries with seq >= this.
        #[arg(long)]
        since_seq: Option<u64>,
        /// Newest-first cap.
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },

    /// Every state a path passed through, with blob availability.
    History {
        #[arg(long)]
        session: String,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
        #[arg(long)]
        path: String,
        #[arg(long)]
        json: bool,
    },

    /// Prune intermediate content versions. Baselines are never evicted.
    Gc {
        #[arg(long)]
        session: String,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
        /// Intermediate versions kept per path, beyond baseline and current.
        #[arg(long, default_value_t = 5)]
        keep: usize,
        #[arg(long)]
        dry_run: bool,
    },

    /// Storage and activity summary.
    Status {
        #[arg(long)]
        session: String,
        #[arg(long)]
        ledger_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },

    /// Read one NDJSON request and write one NDJSON response.
    Run {
        /// `-` reads from stdin.
        #[arg(long, default_value = "-")]
        request: String,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ModeArg {
    Auto,
    Overlay,
    Snapshot,
}

impl From<ModeArg> for Mode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Auto => Mode::Auto,
            ModeArg::Overlay => Mode::Overlay,
            ModeArg::Snapshot => Mode::Snapshot,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("wsbox: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Capabilities { json } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "capabilities".into(),
                params: serde_json::json!({}),
                id: None,
            });
            if json {
                print_json(&response)?;
            } else {
                print_capabilities(&response);
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Open {
            session,
            workspace,
            mode,
            ledger_dir,
        } => {
            let params = SessionOpenParams {
                session,
                workspace,
                ledger_dir,
                mode: mode.into(),
                copy_mode: Default::default(),
            };
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "session.open".into(),
                params: to_value(&params)?,
                id: None,
            });
            print_json(&response)?;
            if let Some(result) = &response.result
                && let Some(degraded) = result.get("degraded").and_then(|v| v.as_str())
            {
                eprintln!("warning: {degraded}");
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Exec {
            session,
            call: call_id,
            cwd,
            ledger_dir,
            timeout_ms,
            allow_network,
            read_only,
            passthrough,
            json,
            argv,
        } => {
            let workspace = workspace_of(&session, ledger_dir.as_deref())?;
            let cwd = cwd.unwrap_or_else(|| workspace.clone());
            let passthrough: Vec<PathBuf> = passthrough
                .iter()
                .map(|path| {
                    if path.is_absolute() {
                        path.clone()
                    } else {
                        workspace.join(path)
                    }
                })
                .collect();

            let params = ExecParams {
                session,
                call: call_id,
                cwd,
                argv,
                spec: Spec {
                    enabled: true,
                    backend: Backend::Auto,
                    writable_roots: if read_only {
                        Vec::new()
                    } else {
                        vec![workspace]
                    },
                    passthrough,
                    network: if allow_network {
                        Network::Allow
                    } else {
                        Network::Deny
                    },
                    max_open_files: Some(4096),
                },
                ledger_dir,
                timeout_ms: Some(timeout_ms),
                max_output_bytes: Some(64 * 1024),
            };

            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "exec".into(),
                params: to_value(&params)?,
                id: None,
            });

            if json {
                print_json(&response)?;
                return Ok(ExitCode::SUCCESS);
            }
            if !response.ok {
                return Err(error_message(&response));
            }

            if let Some(result) = &response.result {
                let stdout = result.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
                let stderr = result.get("stderr").and_then(|v| v.as_str()).unwrap_or("");
                print!("{stdout}");
                if !stdout.is_empty() && !stdout.ends_with('\n') {
                    println!();
                }
                eprint!("{stderr}");
                print_change_summary(result);
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Changes {
            session,
            ledger_dir,
            json,
        } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "changes".into(),
                params: to_value(&SessionRef {
                    session,
                    ledger_dir,
                })?,
                id: None,
            });
            if json {
                print_json(&response)?;
            } else if response.ok {
                if let Some(result) = &response.result {
                    print_change_summary(result);
                }
            } else {
                return Err(error_message(&response));
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Apply {
            session,
            ledger_dir,
            force,
        } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "apply".into(),
                params: to_value(&ApplyParams {
                    session,
                    ledger_dir,
                    force,
                })?,
                id: None,
            });
            print_json(&response)?;
            if response.ok
                && response
                    .result
                    .as_ref()
                    .and_then(|r| r.get("ok"))
                    .and_then(|v| v.as_bool())
                    == Some(false)
            {
                return Ok(ExitCode::FAILURE);
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Restore {
            session,
            ledger_dir,
            all,
            path,
        } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "restore".into(),
                params: to_value(&RestoreParams {
                    session,
                    ledger_dir,
                    all,
                    path,
                })?,
                id: None,
            });
            print_json(&response)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Discard {
            session,
            ledger_dir,
        } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "session.discard".into(),
                params: to_value(&SessionRef {
                    session,
                    ledger_dir,
                })?,
                id: None,
            });
            print_json(&response)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Verify {
            session,
            ledger_dir,
        } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "ledger.verify".into(),
                params: to_value(&SessionRef {
                    session,
                    ledger_dir,
                })?,
                id: None,
            });
            print_json(&response)?;
            if !response.ok {
                return Ok(ExitCode::FAILURE);
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Query {
            session,
            ledger_dir,
            call,
            path,
            since_seq,
            limit,
            json,
        } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "ledger.query".into(),
                params: to_value(&LedgerQueryParams {
                    session,
                    ledger_dir,
                    call,
                    path,
                    since_seq,
                    limit,
                })?,
                id: None,
            });
            if json {
                print_json(&response)?;
            } else if response.ok {
                if let Some(result) = &response.result {
                    print_ledger(result);
                }
            } else {
                return Err(error_message(&response));
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::History {
            session,
            ledger_dir,
            path,
            json,
        } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "history".into(),
                params: to_value(&HistoryParams {
                    session,
                    ledger_dir,
                    path,
                })?,
                id: None,
            });
            if json {
                print_json(&response)?;
            } else if response.ok {
                if let Some(result) = &response.result {
                    print_history(result);
                }
            } else {
                return Err(error_message(&response));
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Gc {
            session,
            ledger_dir,
            keep,
            dry_run,
        } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "gc".into(),
                params: to_value(&GcParams {
                    session,
                    ledger_dir,
                    keep,
                    dry_run,
                })?,
                id: None,
            });
            print_json(&response)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Status {
            session,
            ledger_dir,
            json,
        } => {
            let response = wsbox::dispatch(&Envelope {
                protocol: PROTOCOL_VERSION,
                method: "status".into(),
                params: to_value(&SessionRef {
                    session,
                    ledger_dir,
                })?,
                id: None,
            });
            if json {
                print_json(&response)?;
            } else if response.ok {
                if let Some(result) = &response.result {
                    print_status(result);
                }
            } else {
                return Err(error_message(&response));
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Run { request } => {
            let mut input: Box<dyn BufRead> = if request == "-" {
                Box::new(BufReader::new(std::io::stdin()))
            } else {
                let file = std::fs::File::open(&request)
                    .map_err(|error| format!("cannot read {request}: {error}"))?;
                Box::new(BufReader::new(file))
            };
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            wsbox::run_once(&mut input, &mut output).map_err(|error| error.to_string())?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

fn print_json(response: &Response) -> Result<(), String> {
    let text = serde_json::to_string_pretty(response).map_err(|error| error.to_string())?;
    println!("{text}");
    Ok(())
}

fn error_message(response: &Response) -> String {
    response
        .error
        .as_ref()
        .map(|error| format!("{}: {}", error.code, error.message))
        .unwrap_or_else(|| "request failed".to_string())
}

fn print_capabilities(response: &Response) {
    let Some(result) = &response.result else {
        eprintln!("{}", error_message(response));
        return;
    };
    let flag = |key: &str| {
        result
            .get(key)
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    };
    println!(
        "platform          {}",
        result
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
    );
    println!("user namespaces   {}", yes_no(flag("userNamespace")));
    println!("overlayfs         {}", yes_no(flag("overlayfs")));
    println!("bubblewrap        {}", yes_no(flag("bubblewrap")));
    println!("seccomp           {}", yes_no(flag("seccomp")));
    println!("fuse              {}", yes_no(flag("fuse")));
    println!(
        "landlock ABI      {}",
        result
            .get("landlockAbi")
            .and_then(|v| v.as_u64())
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unavailable".into())
    );
    if let Some(detail) = result.get("detail").and_then(|v| v.as_str()) {
        println!("\n{detail}");
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn print_change_summary(result: &serde_json::Value) {
    let exit_code = result.get("exitCode").and_then(|v| v.as_i64());
    let timed_out = result
        .get("timedOut")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if let Some(code) = exit_code {
        let suffix = if timed_out { " (timed out)" } else { "" };
        eprintln!("exit code {code}{suffix}");
    }

    let Some(changes) = result.get("changes").and_then(|v| v.as_array()) else {
        return;
    };
    if changes.is_empty() {
        eprintln!("(no workspace changes)");
        return;
    }

    let mut suspicious = Vec::new();
    eprintln!("\n{} file(s) changed:", changes.len());
    for change in changes {
        let path = change.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let op = change.get("op").and_then(|v| v.as_str()).unwrap_or("?");
        let before = change.get("beforeBytes").and_then(|v| v.as_u64());
        let after = change.get("afterBytes").and_then(|v| v.as_u64());
        let size = match (before, after) {
            (Some(b), Some(a)) => format!("{b} -> {a} bytes"),
            (None, Some(a)) => format!("new, {a} bytes"),
            (Some(b), None) => format!("deleted, was {b} bytes"),
            (None, None) => String::new(),
        };
        let marker = if change
            .get("suspicious")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            "  <== suspicious"
        } else {
            ""
        };
        eprintln!("  {op:<7} {path}  {size}{marker}");

        if let Some(diff) = change.get("diff").and_then(|v| v.as_str()) {
            let total = diff.lines().count();
            for line in diff.lines().take(12) {
                eprintln!("      {line}");
            }
            if total > 12 {
                eprintln!("      [... {} more diff lines ...]", total - 12);
            }
        }
        if let Some(reason) = change.get("reason").and_then(|v| v.as_str()) {
            suspicious.push(format!("{path}: {reason}"));
        }
    }

    if !suspicious.is_empty() {
        eprintln!("\nwarning: this call removed most of a file's content:");
        for line in suspicious {
            eprintln!("  {line}");
        }
        eprintln!("use `wsbox restore --session <id> --path <path>` if that was not intended.");
    }
}

fn workspace_of(session: &str, ledger_dir: Option<&std::path::Path>) -> Result<PathBuf, String> {
    let dir = ledger_dir
        .map(PathBuf::from)
        .unwrap_or_else(wsbox::session::default_ledger_dir);
    let path = wsbox::session::Session::root_for(&dir, session).join("session.json");
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("cannot read session {}: {error}", path.display()))?;
    let meta: wsbox::session::SessionMeta =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    Ok(meta.workspace)
}

fn print_ledger(result: &serde_json::Value) {
    let entries = result
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let total = result.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    let ledger_entries = result
        .get("ledgerEntries")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if entries.is_empty() {
        println!("no matching entries ({ledger_entries} in the ledger)");
        return;
    }
    println!("{total} matching of {ledger_entries} ledger entries (newest first):\n");
    for entry in &entries {
        let seq = entry.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
        let call = entry.get("call").and_then(|v| v.as_str()).unwrap_or("?");
        let exit = entry.get("exitCode").and_then(|v| v.as_i64()).unwrap_or(0);
        let argv = entry
            .get("argv")
            .and_then(|v| v.as_array())
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        println!("[{seq}] {call}  exit={exit}");
        println!("      $ {}", truncate(&argv, 120));
        if let Some(changes) = entry.get("changes").and_then(|v| v.as_array()) {
            for change in changes {
                let path = change.get("path").and_then(|v| v.as_str()).unwrap_or("?");
                let op = change.get("op").and_then(|v| v.as_str()).unwrap_or("?");
                let flag = if change
                    .get("suspicious")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    "  <== suspicious"
                } else {
                    ""
                };
                println!("      {op:<7} {path}{flag}");
            }
        }
    }
}

fn print_history(result: &serde_json::Value) {
    let path = result.get("path").and_then(|v| v.as_str()).unwrap_or("?");
    let baseline = result.get("baselineSha").and_then(|v| v.as_str());
    let available = result
        .get("baselineAvailable")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    println!("history of {path}\n");
    match baseline {
        Some(sha) => println!(
            "  baseline  {sha:.12}  {}\n",
            if available { "available" } else { "PRUNED" }
        ),
        None => println!("  baseline  (did not exist)\n"),
    }

    let versions = result
        .get("versions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if versions.is_empty() {
        println!("  no recorded changes");
        return;
    }

    for version in &versions {
        let seq = version.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
        let call = version.get("call").and_then(|v| v.as_str()).unwrap_or("?");
        let op = version.get("op").and_then(|v| v.as_str()).unwrap_or("?");
        let after = version.get("afterSha").and_then(|v| v.as_str());
        let after_ok = version
            .get("afterAvailable")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let before_ok = version
            .get("beforeAvailable")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let digest = after
            .map(|sha| format!("{:.12}", sha))
            .unwrap_or_else(|| "(absent)".into());
        println!(
            "  [{seq}] {op:<7} -> {digest}  {call}   before:{}{}",
            if before_ok { "ok" } else { "pruned" },
            if after_ok { "" } else { "  after:pruned" }
        );
    }
    println!("\n  `wsbox restore --session <id> --path {path}` returns to the baseline.");
}

fn print_status(result: &serde_json::Value) {
    let number = |key: &str| result.get(key).and_then(|v| v.as_u64()).unwrap_or(0);
    let text = |key: &str| {
        result
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string()
    };

    let cas = number("casBytes");
    let naive = number("naiveSnapshotBytes");
    let workspace = number("workspaceBytes");
    println!("session     {}", text("session"));
    println!("workspace   {}", text("workspace"));
    println!("mode        {}", text("mode"));
    println!("calls       {}", number("calls"));
    println!("changed     {} path(s)", number("changedPaths"));
    println!();
    println!(
        "ledger      {} entries, {} bytes",
        number("ledgerEntries"),
        number("ledgerBytes")
    );
    println!("cas         {} blobs, {} bytes", number("casBlobs"), cas);
    println!();
    println!("workspace   {workspace} bytes of content");
    if naive > 0 {
        let verdict = if cas <= naive {
            "cheaper"
        } else {
            "MORE EXPENSIVE"
        };
        println!(
            "snapshot    {naive} bytes if the whole tree were copied before each call \
             (cas is {verdict})"
        );
    }
    if cas > naive && naive > 0 {
        println!(
            "\n  A single large file rewritten with distinct content every call is the worst\n  \
             case for content addressing — deduplication cannot help. Run `wsbox gc` to keep\n  \
             only the baseline, the current state, and the last few intermediates."
        );
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let head: String = text.chars().take(max).collect();
    format!("{head}...")
}
