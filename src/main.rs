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
    ApplyParams, Backend, Envelope, ExecParams, Mode, Network, PROTOCOL_VERSION, Response,
    RestoreParams, SessionOpenParams, SessionRef, Spec,
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
            json,
            argv,
        } => {
            let workspace = workspace_of(&session, ledger_dir.as_deref())?;
            let cwd = cwd.unwrap_or_else(|| workspace.clone());

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
