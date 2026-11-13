// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Cursor, Read, Write};
use std::sync::mpsc;
use std::thread;

use passmcp_sdk::{
    client::McpClient,
    http::{HttpRequest, HttpServerHandler, HttpTransport, HEADER_METHOD, HEADER_PROTOCOL_VERSION},
    oauth::{
        compute_s256_challenge, generate_verifier, generate_verifier_from_seed, verify_s256,
        AuthorizationServerMetadata, BearerChallenge, ProtectedResourceMetadata,
    },
    server::McpServer,
    stdio::StdioTransport,
    types::{
        CacheHints, CallToolResult, ContentBlock, GetPromptResult, Prompt, PromptArgs,
        PromptArgument, PromptMessage, RpcError, SdkError, Tool, ToolAnnotations,
        CACHE_SCOPE_PUBLIC, CODE_HEADER_MISMATCH, CODE_INVALID_PARAMS, CODE_METHOD_NOT_FOUND,
        CODE_PARSE_ERROR, CODE_UNSUPPORTED_PROTOCOL_VERSION, REVISION_2025_11_25,
        REVISION_2026_07_28,
    },
};
use serde_json::{json, Value};

fn build_strict_server() -> McpServer {
    let hints = CacheHints::from_seconds(true, 300, CACHE_SCOPE_PUBLIC).expect("hints");
    let mut srv = McpServer::new("strict-rust", "0.0.10")
        .with_cache_hints(hints)
        .with_allowed_origins(["https://console.example.com"]);
    srv.register_checked_tool(
        Tool {
            name: "inspect".into(),
            title: Some("Inspect".into()),
            description: Some("Inspect typed arguments and return structuredContent".into()),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["endpoint", "retries"],
                "properties": {
                    "endpoint": {"type": "string"},
                    "retries": {"type": "integer"},
                    "ratio": {"type": "number"},
                    "verbose": {"type": "boolean"},
                    "tags": {"type": "array"},
                    "meta": {"type": "object"}
                }
            }),
            output_schema: Some(json!({"type": "object", "required": ["endpoint"]})),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(true),
                ..ToolAnnotations::default()
            }),
        },
        |args| {
            let ep = args
                .get("endpoint")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if ep.is_empty() {
                return Err(RpcError {
                    code: CODE_INVALID_PARAMS,
                    message: "endpoint must not be empty".into(),
                    data: None,
                });
            }
            Ok(CallToolResult::structured(
                format!("ok:{ep}"),
                json!({"endpoint": ep}),
            ))
        },
    );
    srv.register_prompt(
        Prompt {
            name: "audit".into(),
            title: Some("Audit".into()),
            description: Some("Audit prompt".into()),
            arguments: vec![PromptArgument {
                name: "server_name".into(),
                description: Some("Target server name".into()),
                required: true,
            }],
        },
        |args| {
            Ok(GetPromptResult {
                description: None,
                messages: vec![PromptMessage {
                    role: "user".into(),
                    content: ContentBlock::text(format!("audit {}", args["server_name"])),
                }],
            })
        },
    );
    srv
}

#[test]
fn discover_metadata_and_negative_schema_validation() {
    let srv = build_strict_server();
    let mut cli = McpClient::new(&srv);

    let disc = cli.discover().expect("discover");
    assert_eq!(disc.result_type.as_deref(), Some("discover"));
    assert_eq!(disc.supported_versions.len(), 3);
    let meta = disc.meta.expect("meta");
    assert_eq!(meta.ttl_ms, 300_000);
    assert_eq!(
        meta.server_info.as_ref().map(|i| i.name.as_str()),
        Some("strict-rust")
    );

    let ok = cli
        .call_tool(
            "inspect",
            json!({
                "endpoint": "https://mcp.example.com/mcp",
                "retries": 2,
                "ratio": 0.5,
                "verbose": true,
                "tags": ["a"],
                "meta": {"k": "v"}
            }),
        )
        .expect("valid call");
    assert_eq!(
        ok.structured_content,
        Some(json!({"endpoint": "https://mcp.example.com/mcp"}))
    );

    for bad in [
        json!({"retries": 1}),
        json!({"endpoint": "x", "retries": 1, "extra": true}),
        json!({"endpoint": 42, "retries": 1}),
        json!({"endpoint": "x", "retries": 1.5}),
        json!({"endpoint": "x", "retries": 1, "ratio": "bad"}),
        json!({"endpoint": "x", "retries": 1, "verbose": "no"}),
        json!({"endpoint": "x", "retries": 1, "tags": 1}),
        json!({"endpoint": "x", "retries": 1, "meta": []}),
        json!({"endpoint": "", "retries": 1}),
    ] {
        match cli.call_tool("inspect", bad.clone()) {
            Err(SdkError::Rpc(err)) => assert_eq!(err.code, CODE_INVALID_PARAMS, "bad={bad}"),
            other => panic!("expected -32602 for {bad}, got {other:?}"),
        }
    }

    match cli.get_prompt("audit", &PromptArgs::new()) {
        Err(SdkError::Rpc(err)) => assert_eq!(err.code, CODE_INVALID_PARAMS),
        other => panic!("expected -32602 on missing required prompt arg, got {other:?}"),
    }
}

struct ChanReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

struct ChanWriter {
    tx: mpsc::Sender<Vec<u8>>,
}

impl Write for ChanWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stdio_server_framing_and_stream_plus_spawn_transport() {
    let srv = build_strict_server();
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{truncated-line\n",
        "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n",
    );
    let mut out = Vec::new();
    srv.serve_stdio(Cursor::new(input.as_bytes()), &mut out)
        .expect("serve_stdio");
    let text = String::from_utf8(out).expect("utf8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "notifications must not emit lines: {text}");
    let err_line: Value = serde_json::from_str(lines[0]).expect("json line 0");
    assert_eq!(err_line["error"]["code"], json!(CODE_PARSE_ERROR));
    let ping_line: Value = serde_json::from_str(lines[1]).expect("json line 1");
    assert_eq!(ping_line["id"], json!(9));

    let (c2s_tx, c2s_rx) = mpsc::channel();
    let (s2c_tx, s2c_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let srv = build_strict_server();
        let reader = io::BufReader::new(ChanReader {
            rx: c2s_rx,
            buf: Vec::new(),
            pos: 0,
        });
        srv.serve_stdio(reader, ChanWriter { tx: s2c_tx })
    });

    let mut tr = StdioTransport::from_streams(
        ChanReader {
            rx: s2c_rx,
            buf: Vec::new(),
            pos: 0,
        },
        ChanWriter { tx: c2s_tx },
    );
    let mut cli = McpClient::new(&mut tr);
    cli.connect().expect("stdio connect");
    cli.ping().expect("stdio ping");
    drop(cli);
    tr.close().expect("stdio close");
    worker.join().expect("join").expect("server exit");

    let mut spawned = StdioTransport::spawn(
        "sh",
        [
            "-c",
            "head -n 1 >/dev/null && printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n'",
        ],
    )
    .expect("spawn sh responder");
    let mut proc_cli = McpClient::new(&mut spawned);
    proc_cli.ping().expect("spawned ping");
    drop(proc_cli);
    spawned.close().expect("spawned close");
}

#[test]
fn streamable_http_auth_headers_sessions_and_http1_stream() {
    let srv = build_strict_server();
    let meta_url = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
    let mut handler =
        HttpServerHandler::new(&srv).with_bearer_auth(|tok| tok == "valid-token", meta_url);

    let forbidden = handler.handle(
        &HttpRequest::post("/mcp", b"{}".to_vec()).with_header("Origin", "https://evil.example"),
    );
    assert_eq!(forbidden.status, 403);

    let unauth = handler.handle(&HttpRequest::post("/mcp", b"{}".to_vec()));
    assert_eq!(unauth.status, 401);
    let chal = BearerChallenge::parse(unauth.header("WWW-Authenticate").expect("hdr"))
        .expect("parse challenge");
    assert_eq!(chal.resource_metadata.as_deref(), Some(meta_url));

    let get_req = HttpRequest {
        method: "GET".into(),
        path: "/mcp".into(),
        headers: [("Authorization".into(), "Bearer valid-token".into())].into(),
        body: Vec::new(),
    };
    let method_err = handler.handle(&get_req);
    assert_eq!(method_err.status, 405);
    assert_eq!(method_err.header("Allow"), Some("POST"));

    let bad_json = handler.handle(
        &HttpRequest::post("/mcp", b"{bad".to_vec())
            .with_header("Authorization", "Bearer valid-token"),
    );
    assert_eq!(bad_json.status, 400);

    let mismatch = handler.handle(
        &HttpRequest::post(
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec(),
        )
        .with_header("Authorization", "Bearer valid-token")
        .with_header(HEADER_PROTOCOL_VERSION, REVISION_2026_07_28)
        .with_header(HEADER_METHOD, "tools/call"),
    );
    assert_eq!(mismatch.status, 400);
    let mm_val: Value = serde_json::from_slice(&mismatch.body).expect("mm json");
    assert_eq!(mm_val["error"]["code"], json!(CODE_HEADER_MISMATCH));

    let bad_ver = handler.handle(
        &HttpRequest::post(
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec(),
        )
        .with_header("Authorization", "Bearer valid-token")
        .with_header(HEADER_PROTOCOL_VERSION, "1999-01-01"),
    );
    assert_eq!(bad_ver.status, 400);
    let bv_val: Value = serde_json::from_slice(&bad_ver.body).expect("bv json");
    assert_eq!(
        bv_val["error"]["code"],
        json!(CODE_UNSUPPORTED_PROTOCOL_VERSION)
    );

    let tr = HttpTransport::new("https://mcp.example.com/mcp", &mut handler)
        .with_bearer_token("valid-token")
        .with_stateless_headers(REVISION_2026_07_28);
    let mut cli = McpClient::new(tr);
    cli.connect().expect("http connect + 202 notification");
    match cli.list_resources() {
        Err(SdkError::Rpc(err)) => assert_eq!(err.code, CODE_METHOD_NOT_FOUND),
        other => panic!("expected -32601 over HTTP 404, got {other:?}"),
    }

    verify_http_sessions_and_stream();
}

fn verify_http_sessions_and_stream() {
    let sess_srv = McpServer::new("sess", "0.0.10").with_revision(REVISION_2025_11_25);
    let mut sess_handler = HttpServerHandler::new(&sess_srv).with_sessions(true);
    let bogus = HttpTransport::new("https://mcp.example.com/mcp", &mut sess_handler)
        .with_session_id("forged");
    assert!(matches!(
        McpClient::new(bogus).ping(),
        Err(SdkError::Http { status: 404, .. })
    ));

    let mut good_tr = HttpTransport::new("https://mcp.example.com/mcp", &mut sess_handler);
    {
        let mut cli = McpClient::new(&mut good_tr);
        cli.connect().expect("session initialize");
        cli.ping().expect("session ping");
    }
    assert!(good_tr.session_id().is_some());

    struct Duplex {
        read_buf: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_buf.read(buf)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let raw_http = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).expect("utf8")
    );
    let mut duplex = Duplex {
        read_buf: Cursor::new(raw_http.into_bytes()),
        written: Vec::new(),
    };
    let plain_srv = McpServer::new("plain", "0.0.10");
    HttpServerHandler::new(&plain_srv)
        .serve_http1_stream(&mut duplex)
        .expect("serve_http1_stream");
    let resp_str = String::from_utf8(duplex.written).expect("utf8 resp");
    assert!(resp_str.starts_with("HTTP/1.1 200 OK\r\n"));
}

#[test]
fn oauth21_pkce_challenges_and_metadata_discovery() {
    let rfc7636_seed: [u8; 32] = [
        116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37,
        77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
    ];
    let vec_verifier = generate_verifier_from_seed(&rfc7636_seed);
    assert_eq!(vec_verifier, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let vec_challenge = compute_s256_challenge(&vec_verifier).expect("rfc7636 challenge");
    assert_eq!(vec_challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    assert!(verify_s256(&vec_verifier, &vec_challenge));
    assert!(!verify_s256(&vec_verifier, "tampered"));

    let v1 = generate_verifier().expect("v1");
    let v2 = generate_verifier().expect("v2");
    assert_ne!(v1, v2);
    assert!((43..=128).contains(&v1.len()));
    assert!(compute_s256_challenge("too-short").is_err());

    let chal = BearerChallenge {
        resource_metadata: Some(
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp".into(),
        ),
        scope: Some("mcp:tools".into()),
        error: Some("invalid_token".into()),
        error_description: Some("Token expired".into()),
    };
    let parsed = BearerChallenge::parse(&chal.header_value()).expect("roundtrip challenge");
    assert_eq!(parsed, chal);

    let (path_url, root_url) =
        ProtectedResourceMetadata::well_known_urls("https://MCP.example.com/mcp/").expect("urls");
    assert_eq!(
        path_url,
        "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
    );
    assert_eq!(
        root_url,
        "https://mcp.example.com/.well-known/oauth-protected-resource"
    );
    let prm = ProtectedResourceMetadata {
        resource: "https://mcp.example.com/mcp".into(),
        authorization_servers: vec!["https://auth.example.com".into()],
        scopes_supported: vec!["mcp:tools".into()],
    };
    prm.validate_resource_binding("https://MCP.example.com/mcp/")
        .expect("binding ok");
    assert!(prm
        .validate_resource_binding("https://evil.example.com/mcp")
        .is_err());

    let as_url =
        AuthorizationServerMetadata::well_known_url("https://auth.example.com/tenant").expect("as");
    assert_eq!(
        as_url,
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant"
    );
    let asm = AuthorizationServerMetadata {
        issuer: "https://auth.example.com/tenant".into(),
        authorization_endpoint: "https://auth.example.com/authorize".into(),
        token_endpoint: "https://auth.example.com/token".into(),
        registration_endpoint: None,
        code_challenge_methods_supported: vec!["S256".into()],
    };
    asm.validate_oauth21(Some("https://auth.example.com/tenant/"))
        .expect("oauth21 ok");
    let mut no_pkce = asm.clone();
    no_pkce.code_challenge_methods_supported = vec!["plain".into()];
    assert!(no_pkce.validate_oauth21(None).is_err());
}
