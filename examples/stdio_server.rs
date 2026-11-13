// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, BufReader};

use passmcp_sdk::{
    server::McpServer,
    types::{
        CacheHints, CallToolResult, ContentBlock, GetPromptResult, JsonObject, Prompt,
        PromptArgument, PromptMessage, Resource, ResourceContents, RpcError, Tool, ToolAnnotations,
        CACHE_SCOPE_PUBLIC, CODE_INVALID_PARAMS,
    },
};
use serde_json::{json, Value};

fn main() -> io::Result<()> {
    let srv = build_demo_server();
    let stdin = io::stdin();
    let stdout = io::stdout();
    srv.serve_stdio(BufReader::new(stdin.lock()), stdout.lock())
}

fn build_demo_server() -> McpServer {
    let hints = CacheHints::from_seconds(true, 300, CACHE_SCOPE_PUBLIC)
        .expect("valid SEP-2549 public cache hints");
    let mut srv = McpServer::new("passmcp-sdk-rust-demo", "0.0.9")
        .with_instructions(
            "Reference MCP server built with passmcp-sdk demonstrating read-only tools, SEP-2164 resources, prompts, and SEP-2549 cache hints.",
        )
        .with_cache_hints(hints);
    register_inspect_tool(&mut srv);
    register_overview_resource(&mut srv);
    register_audit_prompt(&mut srv);
    srv
}

fn register_inspect_tool(srv: &mut McpServer) {
    let tool = Tool {
        name: "inspect_target".into(),
        title: Some("Inspect MCP Target".into()),
        description: Some(
            "Inspect an HTTPS or stdio MCP target endpoint and report its transport binding without modifying server state."
                .into(),
        ),
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["endpoint"],
            "properties": {
                "endpoint": {
                    "type": "string",
                    "description": "HTTPS or stdio target endpoint identifier to inspect"
                }
            }
        }),
        output_schema: Some(json!({
            "type": "object",
            "required": ["endpoint", "transport"],
            "properties": {
                "endpoint": {"type": "string"},
                "transport": {"type": "string"}
            }
        })),
        annotations: Some(ToolAnnotations {
            title: Some("Inspect MCP Target".into()),
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(false),
        }),
    };
    srv.register_checked_tool(tool, handle_inspect_target);
}

fn handle_inspect_target(args: &JsonObject) -> Result<CallToolResult, RpcError> {
    let endpoint = args
        .get("endpoint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| RpcError {
            code: CODE_INVALID_PARAMS,
            message: "argument \"endpoint\" must be a non-empty string".into(),
            data: None,
        })?;
    let lower = endpoint.to_ascii_lowercase();
    let transport = if lower.starts_with("https://") || lower.starts_with("http://") {
        "http"
    } else {
        "stdio"
    };
    Ok(CallToolResult::structured(
        format!("Target {endpoint} uses {transport} transport."),
        json!({ "endpoint": endpoint, "transport": transport }),
    ))
}

fn register_overview_resource(srv: &mut McpServer) {
    srv.register_resource(
        Resource {
            uri: "passmcp://sdk/overview".into(),
            name: "sdk-overview".into(),
            title: Some("SDK Overview".into()),
            description: Some(
                "Overview of the passmcp SDK capabilities and supported MCP revisions.".into(),
            ),
            mime_type: Some("text/plain".into()),
        },
        |uri| {
            Ok(ResourceContents {
                uri: uri.to_string(),
                mime_type: Some("text/plain".into()),
                text: Some(
                    "passmcp-sdk supports MCP revisions 2026-07-28, 2025-11-25, and 2025-06-18 over stdio and Streamable HTTP."
                        .into(),
                ),
            })
        },
    );
}

fn register_audit_prompt(srv: &mut McpServer) {
    srv.register_prompt(
        Prompt {
            name: "audit_summary".into(),
            title: Some("Audit Summary Prompt".into()),
            description: Some(
                "Generate a concise audit summary prompt for a named MCP server.".into(),
            ),
            arguments: vec![PromptArgument {
                name: "server_name".into(),
                description: Some("Name of the MCP server being audited".into()),
                required: true,
            }],
        },
        |args| {
            let name = args.get("server_name").map(String::as_str).unwrap_or("");
            Ok(GetPromptResult {
                description: Some(format!("Audit summary prompt for {name}")),
                messages: vec![PromptMessage {
                    role: "user".into(),
                    content: ContentBlock::text(format!(
                        "Summarize the MCP conformance and attestation posture for {name}."
                    )),
                }],
            })
        },
    );
}
