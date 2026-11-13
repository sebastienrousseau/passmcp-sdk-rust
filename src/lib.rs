// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Apache-2.0 Rust MCP client and server SDK (`passmcp-sdk`) with
//! capability-gated `2026-07-28` conformance, `stdio` and Streamable `http`
//! transports, OAuth 2.1 S256 PKCE + metadata discovery, and offline `passmcp`
//! attestation verification.
//!
//! # Example
//!
//! ```no_run
//! use passmcp_sdk::{attestation::Statement, server::McpServer, types::Tool};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut srv = McpServer::new("billing", "0.0.10");
//!     srv.register_tool(Tool::read_only("health", "Read-only health probe"), |_args| {
//!         Ok("ok".to_string())
//!     });
//!
//!     let bytes = std::fs::read("testdata/statement.json")?;
//!     let st = Statement::parse(&bytes)?;
//!     assert!(st.covers("http", "https://mcp.example.com/mcp"));
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Offline `in-toto` (`mcp-evaluation/v1`) statement parsing and verification.
pub mod attestation;
/// Policy-enforcing MCP JSON-RPC 2.0 client and attestation admission gate.
pub mod client;
mod error;
/// Streamable HTTP server handler, HTTP/1.1 stream adapter, and client transport.
pub mod http;
/// OAuth 2.1 S256 PKCE, `WWW-Authenticate` challenges, and RFC 9728/8414 metadata.
pub mod oauth;
mod origin;
mod schema;
/// Capability-derived MCP JSON-RPC 2.0 server and HTTP `Origin` allowlist guard.
pub mod server;
/// Newline-delimited UTF-8 `stdio` server loop and client stream/process transport.
pub mod stdio;
/// Shared MCP protocol revisions, wire payloads, cache metadata, and error types.
pub mod types;
