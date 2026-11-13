// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use passmcp_sdk::{attestation::Statement, client::McpClient, server::McpServer, types::Tool};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut srv = McpServer::new("billing", "0.0.10");
    srv.register_tool(
        Tool::read_only("health", "Read-only health probe"),
        |_args| Ok("ok".to_string()),
    );

    let bytes = std::fs::read("testdata/statement.json")?;
    let st = Statement::parse(&bytes)?;
    assert!(st.covers("http", "https://mcp.example.com/mcp"));

    let grade = st
        .predicate
        .score
        .as_ref()
        .map(|s| s.grade.clone())
        .unwrap_or_else(|| "unscored".to_string());

    let mut client =
        McpClient::new(&srv).with_required_attestation(st, "http", "https://mcp.example.com/mcp");
    let disc = client.discover()?;
    let res = client.call_tool("health", json!({}))?;
    let text = res.content[0].text.as_deref().unwrap_or("");

    println!(
        "server={} protocol={} tools={} health={} grade={}",
        srv.info().name,
        disc.protocol_version,
        disc.tools.len(),
        text,
        grade,
    );
    Ok(())
}
