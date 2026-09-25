//! wsbox error type.
//!
//! Every failure carries enough context to be actionable: the caller is an
//! agent that has to decide whether to degrade, retry or abort.

use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("io error: {0}")]
    IoBare(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("invalid request: {0}")]
    Invalid(String),

    #[error("session {0} not found")]
    SessionNotFound(String),

    #[error("session {0} already exists")]
    SessionExists(String),

    #[error("sandbox setup failed: {0}")]
    Sandbox(String),

    #[error("apply conflict on {path}: {detail}")]
    Conflict { path: String, detail: String },

    #[error("protocol version {got} is not supported (this build speaks {expected})")]
    ProtocolVersion { got: u32, expected: u32 },

    #[error("command failed to start: {0}")]
    Spawn(String),
}

impl Error {
    /// Attach a path to a bare io error. Used at every filesystem call site so
    /// the message names the file instead of just the errno.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Stable machine-readable code for the protocol `error.code` field.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } | Self::IoBare(_) => "io",
            Self::Json(_) => "json",
            Self::Unsupported(_) => "unsupported",
            Self::Invalid(_) => "invalid_request",
            Self::SessionNotFound(_) => "session_not_found",
            Self::SessionExists(_) => "session_exists",
            Self::Sandbox(_) => "sandbox",
            Self::Conflict { .. } => "conflict",
            Self::ProtocolVersion { .. } => "protocol_version",
            Self::Spawn(_) => "spawn",
        }
    }
}
