<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to passmcp-sdk-rust are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions are
[Semantic Versioning](https://semver.org/) shaped.

**This repository carries passmcp's version.** It is in lockstep with
[passmcp](https://github.com/sebastienrousseau/passmcp) ([ADR 0013](https://github.com/sebastienrousseau/passmcp/blob/main/docs/adr/0013-language-sdks-are-apache-satellites.md)):
it starts at `Status: Unreleased` on `feat/v0.0.10` and joins the family
release stream with its first signed tag.

## [Unreleased]

## [0.0.10] - 2026-11-13

### Added

- **Initial Rust MCP client and server core (`passmcp-sdk`)** covering MCP
  revisions `2025-06-18`, `2025-11-25`, and `2026-07-28`: capability-gated
  JSON-RPC 2.0 dispatch (`initialize`, `ping`, stateless `server/discover`,
  `tools/list`, `tools/call` with `inputSchema` validation and
  `structuredContent`, `resources/list`, `resources/templates/list`,
  `resources/read`, `prompts/list`, `prompts/get`), SEP-2164 unknown-resource
  errors (`-32602` with `error.data.uri` on `2026-07-28`), SEP-2549 list cache
  hints (`ttlMs` and `cacheScope`), and read-only-by-default client tool
  execution policy (`readOnlyHint: true`).
- **Complete `stdio` and Streamable `http` transports**: newline-delimited
  UTF-8 `serve_stdio` and `StdioTransport` (in-memory streams and spawned child
  processes), plus `HttpServerHandler`, `serve_http1_stream`, and
  `HttpTransport` with strict `OriginGuard` checking, RFC 9728 `401`
  `WWW-Authenticate` Bearer challenges, `-32020` mirrored routing header
  validation, stateless `404` `-32601` responses, and optional `Mcp-Session-Id`
  session management.
- **OAuth 2.1, S256 PKCE, and metadata discovery (`passmcp_sdk::oauth`)**:
  RFC 7636 `generate_verifier`, `compute_s256_challenge`, and constant-time
  `verify_s256`, `WWW-Authenticate` Bearer challenge builder and parser,
  RFC 9728 Protected Resource Metadata URL derivation and resource-binding
  validation, and RFC 8414 Authorization Server Metadata validation.
- **Offline `passmcp` attestation verifier (`passmcp_sdk::attestation`)** for
  `https://in-toto.io/Statement/v1` statements carrying
  `https://satellion.com/attestation/mcp-evaluation/v1`, plus runnable
  `examples/quickstart.rs` and `examples/stdio_server.rs` verified live under
  `passmcp check --stdio` with zero failures and zero warnings.
