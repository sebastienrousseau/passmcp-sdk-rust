// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::attestation::AttestationError;

/// JSON-RPC 2.0 error payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    /// Numeric JSON-RPC error code.
    pub code: i32,
    /// Short error message.
    pub message: String,
    /// Optional structured error data (such as SEP-2164 `{"uri": ...}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rpc error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

/// Unified error type returned by `passmcp-sdk` client, transports, OAuth, and gates.
#[derive(Debug)]
pub enum SdkError {
    /// Invalid SEP-2549 cache hints configuration.
    InvalidCacheHints(String),
    /// Client policy refused a tool invocation (denied or missing `readOnlyHint: true`).
    PolicyViolation(String),
    /// Target attestation failed verification or target coverage.
    Attestation(AttestationError),
    /// Server returned a JSON-RPC 2.0 error object.
    Rpc(RpcError),
    /// Streamable HTTP transport rejected the request with a non-2xx status.
    Http {
        /// HTTP status code (such as `401`, `403`, `404`, `405`).
        status: u16,
        /// Optional `WWW-Authenticate` response challenge header.
        www_authenticate: Option<String>,
    },
    /// OAuth 2.1 PKCE, challenge, or metadata validation failure.
    OAuth(String),
    /// Transport or JSON serialization error.
    Transport(String),
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCacheHints(msg) => write!(f, "mcp: invalid cache hints: {msg}"),
            Self::PolicyViolation(msg) => write!(f, "mcp: policy violation: {msg}"),
            Self::Attestation(err) => write!(f, "mcp: untrusted attestation: {err}"),
            Self::Rpc(err) => write!(f, "mcp: {err}"),
            Self::Http { status, .. } => write!(f, "mcp: unexpected HTTP status {status}"),
            Self::OAuth(msg) => write!(f, "mcp: oauth error: {msg}"),
            Self::Transport(msg) => write!(f, "mcp: transport error: {msg}"),
        }
    }
}

impl std::error::Error for SdkError {}

impl From<AttestationError> for SdkError {
    fn from(value: AttestationError) -> Self {
        Self::Attestation(value)
    }
}
