// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use passmcp_sdk::{
    attestation::{target_descriptor, verify_target, AttestationError, Statement},
    client::{verify_attestation_gate, McpClient, Policy},
    server::{McpServer, OriginGuard},
    types::{
        CacheHints, ContentBlock, GetPromptResult, Prompt, PromptArgs, PromptMessage, Resource,
        ResourceContents, ResourceTemplate, SdkError, Tool, CACHE_SCOPE_PUBLIC,
        CODE_INVALID_PARAMS, CODE_METHOD_NOT_FOUND, CODE_PARSE_ERROR,
        CODE_RESOURCE_NOT_FOUND_LEGACY, REVISION_2025_11_25, REVISION_2026_07_28,
    },
};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};

fn fixture_bytes() -> Vec<u8> {
    std::fs::read("testdata/statement.json").expect("read testdata/statement.json")
}

#[test]
fn readme_quickstart_contract_compiles_and_runs() {
    let mut srv = McpServer::new("billing", "0.0.10");
    srv.register_tool(
        Tool::read_only("health", "Read-only health probe"),
        |_args| Ok("ok".to_string()),
    );

    let bytes = fixture_bytes();
    let st = Statement::parse(&bytes).expect("parse statement.json");
    assert!(st.covers("http", "https://mcp.example.com/mcp"));
    assert!(st.covers("http", "  https://mcp.example.com/mcp  "));
    assert!(!st.covers("stdio", "https://mcp.example.com/mcp"));
    assert_eq!(
        st.verdict_for("auth.unauthenticated_tools")
            .expect("verdict present")
            .status,
        "pass"
    );
    assert!(matches!(
        st.verdict_for("missing.check"),
        Err(AttestationError::NoSuchCheck(_))
    ));
}

#[test]
fn attestation_sha512_and_tampered_cases_rejected() {
    let raw = fixture_bytes();
    let mut doc: Value = serde_json::from_slice(&raw).expect("valid json");

    let desc = target_descriptor("http", "https://mcp.example.com/mcp");
    let sha512 = format!("{:x}", Sha512::digest(desc.as_bytes()));
    doc["subject"][0]["digest"]["sha512"] = Value::String(sha512);
    let both_bytes = serde_json::to_vec(&doc).expect("serialize");
    let st = Statement::parse(&both_bytes).expect("valid sha256 + sha512");
    assert!(st.covers("http", "https://mcp.example.com/mcp"));

    assert_tampered_rejected(&raw, |d| {
        d["subject"][0]["digest"]["sha512"] = json!("0000");
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicate"]["target"]["endpoint"] = json!("https://evil.example.com/mcp");
    });
    assert_tampered_rejected(&raw, |d| {
        d["subject"][0]["name"] = json!("https://evil.example.com/mcp");
    });
    assert_tampered_rejected(&raw, |d| {
        d["_type"] = json!("https://in-toto.io/Statement/v0.1");
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicateType"] = json!("https://example.com/unknown/v1");
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicate"]["subjectKind"] = json!("binary-artifact");
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicate"]["target"]["transport"] = json!("websocket");
    });
}

#[test]
fn attestation_basis_counts_and_policy_gates() {
    let raw = fixture_bytes();
    assert_tampered_rejected(&raw, |d| {
        d["subject"] = json!([]);
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicate"]["instrument"]["name"] = json!("");
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicate"]["ranAt"] = json!("");
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicate"]["verdicts"] = json!([]);
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicate"]["judgedAgainst"]["checkInventory"] = json!("");
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicate"]["judgedAgainst"]["rubric"] = json!("");
    });
    assert_tampered_rejected(&raw, |d| {
        d["predicate"]["counts"]["fail"] = json!(0);
    });

    assert!(verify_target(
        &raw,
        "http",
        "https://mcp.example.com/mcp",
        Some(80.0),
        &["auth"]
    )
    .is_ok());
    assert!(verify_target(&raw, "http", "https://mcp.example.com/mcp", Some(95.0), &[]).is_err());
    assert!(verify_target(
        &raw,
        "http",
        "https://mcp.example.com/mcp",
        Some(80.0),
        &["protocol"]
    )
    .is_err());
    assert!(verify_attestation_gate(
        &raw,
        "http",
        "https://mcp.example.com/mcp",
        Some(80.0),
        &["protocol.origin"]
    )
    .is_err());
}

fn assert_tampered_rejected<F: FnOnce(&mut Value)>(raw: &[u8], mutate: F) {
    let mut doc: Value = serde_json::from_slice(raw).expect("json");
    mutate(&mut doc);
    let bytes = serde_json::to_vec(&doc).expect("serialize");
    assert!(
        Statement::parse(&bytes).is_err(),
        "expected rejection for {doc}"
    );
}

#[test]
fn capability_gating_and_stateless_discover() {
    let srv = McpServer::new("empty", "0.0.10").with_instructions("read-only service");
    assert_eq!(srv.revision(), REVISION_2026_07_28);
    let mut cli = McpClient::new(&srv).with_client_info("test-cli", "0.0.10");

    let init = cli.connect().expect("connect");
    assert!(init.capabilities.tools.is_none());
    assert!(init.capabilities.resources.is_none());
    assert!(init.capabilities.prompts.is_none());
    cli.ping().expect("ping");

    let disc = cli.discover().expect("discover");
    assert_eq!(disc.instructions.as_deref(), Some("read-only service"));
    assert!(disc.meta.is_some());

    assert_rpc_code(cli.list_tools(), CODE_METHOD_NOT_FOUND);
    assert_rpc_code(cli.list_resources(), CODE_METHOD_NOT_FOUND);
    assert_rpc_code(cli.list_resource_templates(), CODE_METHOD_NOT_FOUND);
    assert_rpc_code(cli.read_resource("doc://a"), CODE_METHOD_NOT_FOUND);
    assert_rpc_code(cli.list_prompts(), CODE_METHOD_NOT_FOUND);
    assert_rpc_code(
        cli.get_prompt("p", &PromptArgs::new()),
        CODE_METHOD_NOT_FOUND,
    );
}

fn assert_rpc_code<T: std::fmt::Debug>(res: Result<T, SdkError>, want_code: i32) {
    match res {
        Err(SdkError::Rpc(err)) => assert_eq!(err.code, want_code, "unexpected error: {err}"),
        other => panic!("expected RpcError({want_code}), got {other:?}"),
    }
}

#[test]
fn sep2164_missing_resource_codes_and_data_uri() {
    let mut latest = McpServer::new("res-2026", "0.0.10");
    latest.register_resource(
        Resource {
            uri: "doc://readme".into(),
            name: "readme".into(),
            title: None,
            description: None,
            mime_type: Some("text/plain".into()),
        },
        |uri| {
            Ok(ResourceContents {
                uri: uri.to_string(),
                mime_type: Some("text/plain".into()),
                text: Some("hello".into()),
            })
        },
    );
    latest.register_resource_template(
        ResourceTemplate {
            uri_template: "item://{id}".into(),
            name: "item".into(),
            title: None,
            description: None,
            mime_type: None,
        },
        |uri| {
            Ok(ResourceContents {
                uri: uri.to_string(),
                mime_type: None,
                text: Some("templated".into()),
            })
        },
    );

    let mut cli = McpClient::new(&latest);
    assert_eq!(cli.list_resources().expect("resources").len(), 1);
    assert_eq!(cli.list_resource_templates().expect("templates").len(), 1);
    let ok_read = cli.read_resource("item://99").expect("template read");
    assert_eq!(ok_read.contents[0].text.as_deref(), Some("templated"));

    match cli.read_resource("doc://missing") {
        Err(SdkError::Rpc(err)) => {
            assert_eq!(err.code, CODE_INVALID_PARAMS);
            assert_eq!(err.data, Some(json!({"uri": "doc://missing"})));
        }
        other => panic!("expected SEP-2164 -32602 error, got {other:?}"),
    }

    let mut legacy = McpServer::new("res-2025", "0.0.10").with_revision(REVISION_2025_11_25);
    legacy.register_resource(
        Resource {
            uri: "doc://readme".into(),
            name: "readme".into(),
            title: None,
            description: None,
            mime_type: None,
        },
        |uri| {
            Ok(ResourceContents {
                uri: uri.to_string(),
                mime_type: None,
                text: Some("v1".into()),
            })
        },
    );
    match McpClient::new(&legacy).read_resource("doc://missing") {
        Err(SdkError::Rpc(err)) => {
            assert_eq!(err.code, CODE_RESOURCE_NOT_FOUND_LEGACY);
            assert_eq!(err.data, Some(json!({"uri": "doc://missing"})));
        }
        other => panic!("expected legacy -32002 error, got {other:?}"),
    }
}

#[test]
fn sep2549_cache_hints_and_origin_guard() {
    assert!(CacheHints::new(-1, CACHE_SCOPE_PUBLIC).is_err());
    assert!(CacheHints::new(100, "shared").is_err());
    let valid_hints = CacheHints::new(60_000, CACHE_SCOPE_PUBLIC).expect("valid cache hints");

    let mut srv = McpServer::new("catalog", "0.0.10").with_allowed_origins([
        "https://console.example.com",
        "*",
        "null",
        "https://bad.example/p",
    ]);
    srv.set_cache_hints(valid_hints).expect("set hints");
    srv.register_tool(Tool::read_only("ping_tool", "ro"), |_| Ok("pong"));

    let raw_resp = srv
        .handle_json(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .expect("response bytes");
    let parsed: Value = serde_json::from_slice(&raw_resp).expect("json");
    assert_eq!(parsed["result"]["_meta"]["ttlMs"], json!(60_000));
    assert_eq!(parsed["result"]["_meta"]["cacheScope"], json!("public"));

    let parse_err_bytes = srv.handle_json(b"{not-json").expect("parse err");
    let parse_err_val: Value = serde_json::from_slice(&parse_err_bytes).expect("json");
    assert_eq!(parse_err_val["error"]["code"], json!(CODE_PARSE_ERROR));
    assert!(srv
        .handle_json(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .is_none());

    let guard: &OriginGuard = srv.origin_guard();
    assert!(guard.is_allowed(None));
    assert!(guard.is_allowed(Some("")));
    assert!(guard.is_allowed(Some("https://CONSOLE.example.com/")));
    assert!(!guard.is_allowed(Some("https://evil.example.com")));
    assert!(!guard.is_allowed(Some("null")));
}

#[test]
fn client_policy_read_only_default_prompts_and_attestation_gate() {
    let mut srv = McpServer::new("full", "0.0.10");
    srv.register_tool(Tool::read_only("health", "read-only"), |_| Ok("ok"));
    srv.register_tool(Tool::read_only("denied_ro", "read-only"), |_| Ok("nope"));
    srv.register_tool(Tool::new("drop_table", "mutating"), |_| Ok("dropped"));
    srv.register_prompt(
        Prompt {
            name: "greet".into(),
            title: None,
            description: None,
            arguments: Vec::new(),
        },
        |args| {
            let who = args.get("who").cloned().unwrap_or_else(|| "world".into());
            Ok(GetPromptResult {
                description: None,
                messages: vec![PromptMessage {
                    role: "user".into(),
                    content: ContentBlock::text(format!("hello {who}")),
                }],
            })
        },
    );

    let st = Statement::parse(&fixture_bytes()).expect("statement");
    let mut ro_client = McpClient::new(&srv)
        .with_policy(Policy {
            allow_mutations: false,
            deny: vec!["denied_ro".into()],
        })
        .with_required_attestation(st.clone(), "http", "https://mcp.example.com/mcp");

    assert!(matches!(
        ro_client.call_tool("denied_ro", json!({})),
        Err(SdkError::PolicyViolation(_))
    ));
    assert!(matches!(
        ro_client.call_tool("drop_table", json!({})),
        Err(SdkError::PolicyViolation(_))
    ));
    let ok = ro_client.call_tool("health", json!({})).expect("health");
    assert_eq!(ok.content[0].text.as_deref(), Some("ok"));

    let prompts = ro_client.list_prompts().expect("prompts");
    assert_eq!(prompts.len(), 1);
    let mut pargs = PromptArgs::new();
    pargs.insert("who".into(), "mcp".into());
    let rendered = ro_client.get_prompt("greet", &pargs).expect("get_prompt");
    assert_eq!(
        rendered.messages[0].content.text.as_deref(),
        Some("hello mcp")
    );

    let mut mut_client = McpClient::new(&srv).with_policy(Policy {
        allow_mutations: true,
        deny: Vec::new(),
    });
    assert!(mut_client.call_tool("drop_table", json!({})).is_ok());

    let mut untrusted =
        McpClient::new(&srv).with_required_attestation(st, "http", "https://wrong.example.com/mcp");
    assert!(matches!(
        untrusted.discover(),
        Err(SdkError::Attestation(_))
    ));
}
