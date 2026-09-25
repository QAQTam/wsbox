//! wsbox — a workspace ledger sandbox for coding agents.
//!
//! The premise: an agent that bypasses `edit`/`apply_patch` and rewrites files
//! through `python`, `sed` or a build tool must not be able to make changes
//! that are *invisible*. Isolation alone does not give you that — bubblewrap
//! makes the workspace writable or not writable, and says nothing about what
//! was written.
//!
//! So the engine observes rather than trusts:
//!
//! * every call runs against an overlayfs view whose lower layer is the real
//!   workspace, so the real files are not touched until `apply`;
//! * the upper layer is diffed after each call, and the previous content of
//!   every changed path is already durable in a content-addressed store before
//!   the change is reported;
//! * the result carries a unified diff, so the model sees the damage it caused
//!   through the same channel it uses for everything else.
//!
//! Deliberately free of agent-specific vocabulary: callers hand over a neutral
//! [`protocol::Spec`] (paths and network), not a permission tier.

pub mod capabilities;
pub mod cas;
pub mod diff;
pub mod error;
pub mod fsutil;
pub mod ledger;
pub mod protocol;
pub mod sandbox;
pub mod session;

pub use error::{Error, Result};
pub use protocol::{Envelope, Response};

use std::path::{Path, PathBuf};

/// Route one protocol envelope to the matching operation.
///
/// This is the entire surface a client needs: build an envelope, get a
/// response. Nothing here panics on bad input — a malformed request is a
/// response with `ok: false`.
pub fn dispatch(envelope: &Envelope) -> Response {
    if envelope.protocol != protocol::PROTOCOL_VERSION {
        return Response::err(
            "protocol_version",
            format!(
                "protocol version {} is not supported (this build speaks {})",
                envelope.protocol,
                protocol::PROTOCOL_VERSION
            ),
        )
        .with_id(envelope.id.clone());
    }

    let result = match envelope.method.as_str() {
        "capabilities" => value(capabilities::detect()),

        "session.open" => parse::<protocol::SessionOpenParams>(&envelope.params)
            .and_then(|params| session::Session::open(&params))
            .and_then(|(_, result)| value(result)),

        "exec" => parse::<protocol::ExecParams>(&envelope.params).and_then(|params| {
            let mut session = load_session(params.ledger_dir.as_deref(), &params.session)?;
            let result = session.exec(&params)?;
            value(result)
        }),

        "changes" => parse::<protocol::ChangesParams>(&envelope.params).and_then(|params| {
            let session = load_session(params.ledger_dir.as_deref(), &params.session)?;
            let changes = match &params.call {
                Some(call) => session.changes_for_call(call)?,
                None => session.changes()?,
            };
            value(protocol::ChangesResult {
                session: params.session,
                call: params.call,
                changes,
            })
        }),

        "apply" => parse::<protocol::ApplyParams>(&envelope.params).and_then(|params| {
            let mut session = load_session(params.ledger_dir.as_deref(), &params.session)?;
            let result = session.apply(params.force)?;
            value(result)
        }),

        "restore" => parse::<protocol::RestoreParams>(&envelope.params).and_then(|params| {
            let mut session = load_session(params.ledger_dir.as_deref(), &params.session)?;
            let restored = session.restore(params.path.as_deref(), params.all)?;
            value(serde_json::json!({
                "session": params.session,
                "restored": restored,
            }))
        }),

        "session.discard" => parse::<protocol::SessionRef>(&envelope.params)
            .and_then(|params| discard(params.ledger_dir.as_deref(), &params.session)),

        "ledger.query" => {
            parse::<protocol::LedgerQueryParams>(&envelope.params).and_then(|params| {
                let session = load_session(params.ledger_dir.as_deref(), &params.session)?;
                value(session.query_ledger(&params)?)
            })
        }

        "history" => parse::<protocol::HistoryParams>(&envelope.params).and_then(|params| {
            let session = load_session(params.ledger_dir.as_deref(), &params.session)?;
            value(session.history(&params.path)?)
        }),

        "gc" => parse::<protocol::GcParams>(&envelope.params).and_then(|params| {
            let mut session = load_session(params.ledger_dir.as_deref(), &params.session)?;
            value(session.gc(params.keep, params.dry_run)?)
        }),

        "status" => parse::<protocol::SessionRef>(&envelope.params).and_then(|params| {
            let session = load_session(params.ledger_dir.as_deref(), &params.session)?;
            value(session.status()?)
        }),

        "ledger.verify" => parse::<protocol::SessionRef>(&envelope.params).and_then(|params| {
            let session = load_session(params.ledger_dir.as_deref(), &params.session)?;
            let entries = ledger::verify(&session.ledger_path())?;
            let head = session.ledger_head()?;
            value(serde_json::json!({
                "session": params.session,
                "entries": entries,
                "head": head,
            }))
        }),

        other => {
            return Response::err("unsupported", format!("unknown method `{other}`"))
                .with_id(envelope.id.clone());
        }
    };

    match result {
        Ok(value) => Response::ok(value).with_id(envelope.id.clone()),
        Err(error) => Response::err(error.code(), error.to_string()).with_id(envelope.id.clone()),
    }
}

fn parse<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> Result<T> {
    serde_json::from_value(value.clone()).map_err(Error::Json)
}

/// `serde_json::to_value` returns `serde_json::Error`; normalise it into the
/// engine's error type so the `match` arms stay homogeneous.
fn value<T: serde::Serialize>(input: T) -> Result<serde_json::Value> {
    serde_json::to_value(input).map_err(Error::Json)
}

fn load_session(ledger_dir: Option<&Path>, id: &str) -> Result<session::Session> {
    let dir = ledger_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(session::default_ledger_dir);
    session::Session::load(&dir, id)
}

fn discard(ledger_dir: Option<&Path>, id: &str) -> Result<serde_json::Value> {
    let dir: PathBuf = ledger_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(session::default_ledger_dir);
    let mut session = session::Session::load(&dir, id)?;

    // In snapshot mode the workspace really was written, so discarding has to
    // put it back before the record is dropped. In overlay mode the workspace
    // was never touched and dropping the record is enough.
    let reverted = if session.meta.mode == protocol::Mode::Snapshot {
        session.restore(None, true)?
    } else {
        Vec::new()
    };

    let root = session.root.clone();
    fsutil::remove_tree(&root)?;
    Ok(serde_json::json!({
        "session": id,
        "reverted": reverted,
    }))
}

/// Read one NDJSON request from `input` and write one NDJSON response to
/// `output`. Used by `wsbox run`.
pub fn run_once(input: &mut impl std::io::BufRead, output: &mut impl std::io::Write) -> Result<()> {
    let mut line = String::new();
    let read = input.read_line(&mut line).map_err(Error::IoBare)?;
    if read == 0 {
        return Err(Error::Invalid("empty request".into()));
    }

    let response = match serde_json::from_str::<Envelope>(&line) {
        Ok(envelope) => dispatch(&envelope),
        Err(error) => Response::err("json", format!("malformed request: {error}")),
    };

    serde_json::to_writer(&mut *output, &response)?;
    output.write_all(b"\n").map_err(Error::IoBare)?;
    output.flush().map_err(Error::IoBare)?;
    Ok(())
}
