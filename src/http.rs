// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use serde_json::Value;

use crate::client::Transport;
use crate::oauth::BearerChallenge;
use crate::server::{encode_error, McpServer, RpcRequest};
use crate::types::{
    RpcError, SdkError, CODE_HEADER_MISMATCH, CODE_METHOD_NOT_FOUND, CODE_PARSE_ERROR,
    CODE_UNSUPPORTED_PROTOCOL_VERSION, REVISION_2025_06_18, REVISION_2025_11_25,
    REVISION_2026_07_28,
};

/// MCP Streamable HTTP protocol version header (`2026-07-28` mirrored header).
pub const HEADER_PROTOCOL_VERSION: &str = "MCP-Protocol-Version";
/// MCP Streamable HTTP mirrored RPC method header (`2026-07-28`).
pub const HEADER_METHOD: &str = "MCP-Method";
/// MCP Streamable HTTP session identifier header (`2025-06-18` / `2025-11-25`).
pub const HEADER_SESSION_ID: &str = "Mcp-Session-Id";

static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);
type BearerValidator = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// Transport-independent HTTP request representation for Streamable HTTP.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method (`"POST"`, `"GET"`, ...).
    pub method: String,
    /// Request path or target URI.
    pub path: String,
    /// Case-insensitive HTTP headers.
    pub headers: BTreeMap<String, String>,
    /// Raw request body bytes.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Constructs a `POST` request with `body`.
    pub fn post(path: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: "POST".to_string(),
            path: path.into(),
            headers: BTreeMap::new(),
            body: body.into(),
        }
    }

    /// Inserts or replaces an HTTP header on the request.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Looks up a header value case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Transport-independent HTTP response representation for Streamable HTTP.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (`200`, `202`, `400`, `401`, `403`, `404`, `405`).
    pub status: u16,
    /// Response headers.
    pub headers: BTreeMap<String, String>,
    /// Raw response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    fn json(status: u16, body: Vec<u8>) -> Self {
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        Self {
            status,
            headers,
            body,
        }
    }

    /// Looks up a response header case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Streamable HTTP server handler wrapping [`McpServer`] with `OriginGuard`,
/// optional Bearer auth (`401` + `WWW-Authenticate`), `-32020` mirrored header
/// checks, stateless `404` `-32601` mapping, and optional `Mcp-Session-Id` state.
pub struct HttpServerHandler<'a> {
    server: &'a McpServer,
    bearer_auth: Option<(BearerValidator, String)>,
    sessions_enabled: bool,
    sessions: BTreeSet<String>,
}

impl<'a> HttpServerHandler<'a> {
    /// Wraps `server` in a Streamable HTTP handler.
    pub fn new(server: &'a McpServer) -> Self {
        Self {
            server,
            bearer_auth: None,
            sessions_enabled: false,
            sessions: BTreeSet::new(),
        }
    }

    /// Configures Bearer token authentication and the RFC 9728 `resource_metadata`
    /// URL advertised on `401 Unauthorized` responses.
    pub fn with_bearer_auth<F>(
        mut self,
        validator: F,
        resource_metadata_url: impl Into<String>,
    ) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.bearer_auth = Some((Box::new(validator), resource_metadata_url.into()));
        self
    }

    /// Enables `Mcp-Session-Id` issuance on `initialize` and `404` rejection of
    /// missing or unknown session headers.
    pub fn with_sessions(mut self, enabled: bool) -> Self {
        self.sessions_enabled = enabled;
        self
    }

    /// Processes a single [`HttpRequest`] in memory without network sockets.
    pub fn handle(&mut self, req: &HttpRequest) -> HttpResponse {
        if !self.server.origin_guard().is_allowed(req.header("Origin")) {
            return HttpResponse::empty(403);
        }
        if let Some(unauth) = self.check_bearer(req) {
            return unauth;
        }
        if !req.method.eq_ignore_ascii_case("POST") {
            let mut resp = HttpResponse::empty(405);
            resp.headers.insert("Allow".to_string(), "POST".to_string());
            return resp;
        }
        self.handle_post(req)
    }

    /// Reads one HTTP/1.1 request from `stream`, dispatches via [`Self::handle`],
    /// and writes an HTTP/1.1 response back to `stream`.
    pub fn serve_http1_stream<S: Read + Write>(&mut self, mut stream: S) -> io::Result<()> {
        let req = read_http1_request(&mut stream)?;
        let resp = self.handle(&req);
        write_http1_response(&mut stream, &resp)
    }

    fn check_bearer(&self, req: &HttpRequest) -> Option<HttpResponse> {
        let (validator, res_meta) = self.bearer_auth.as_ref()?;
        if let Some(tok) = extract_bearer_token(req.header("Authorization")) {
            if validator(tok) {
                return None;
            }
        }
        let challenge = BearerChallenge {
            resource_metadata: (!res_meta.is_empty()).then(|| res_meta.clone()),
            ..BearerChallenge::default()
        };
        let mut resp = HttpResponse::empty(401);
        resp.headers
            .insert("WWW-Authenticate".to_string(), challenge.header_value());
        Some(resp)
    }

    fn handle_post(&mut self, req: &HttpRequest) -> HttpResponse {
        let Ok(parsed) = serde_json::from_slice::<RpcRequest>(&req.body) else {
            return HttpResponse::json(
                400,
                encode_error(Value::Null, CODE_PARSE_ERROR, "Parse error", None),
            );
        };
        if let Some(err_resp) = validate_mirrored_headers(req, &parsed) {
            return err_resp;
        }
        let issued_sid = match self.enforce_session(req, &parsed) {
            Ok(sid) => sid,
            Err(not_found) => return not_found,
        };
        let mut resp = match self.server.handle_json(&req.body) {
            None => HttpResponse::empty(202),
            Some(bytes) => HttpResponse::json(self.status_for_body(&bytes), bytes),
        };
        if let Some(sid) = issued_sid {
            resp.headers.insert(HEADER_SESSION_ID.to_string(), sid);
        }
        resp
    }

    fn enforce_session(
        &mut self,
        req: &HttpRequest,
        parsed: &RpcRequest,
    ) -> Result<Option<String>, HttpResponse> {
        if !self.sessions_enabled {
            return Ok(None);
        }
        if parsed.method == "initialize" && parsed.id.is_some() {
            let sid = format!("sess-{:016x}", SESSION_SEQ.fetch_add(1, Ordering::Relaxed));
            self.sessions.insert(sid.clone());
            return Ok(Some(sid));
        }
        match req.header(HEADER_SESSION_ID).map(str::trim) {
            Some(sid) if self.sessions.contains(sid) => Ok(None),
            _ => Err(HttpResponse::empty(404)),
        }
    }

    fn status_for_body(&self, body: &[u8]) -> u16 {
        if self.server.revision() != REVISION_2026_07_28 {
            return 200;
        }
        #[derive(Deserialize)]
        struct Env {
            error: Option<RpcError>,
        }
        match serde_json::from_slice::<Env>(body) {
            Ok(env)
                if env
                    .error
                    .as_ref()
                    .is_some_and(|e| e.code == CODE_METHOD_NOT_FOUND) =>
            {
                404
            }
            _ => 200,
        }
    }
}

fn extract_bearer_token(header: Option<&str>) -> Option<&str> {
    let trimmed = header?.trim();
    if trimmed.len() <= 7 || !trimmed[..7].eq_ignore_ascii_case("Bearer ") {
        return None;
    }
    let tok = trimmed[7..].trim();
    (!tok.is_empty()).then_some(tok)
}

fn validate_mirrored_headers(req: &HttpRequest, parsed: &RpcRequest) -> Option<HttpResponse> {
    let id = parsed.id.clone().unwrap_or(Value::Null);
    if let Some(ver) = req.header(HEADER_PROTOCOL_VERSION).map(str::trim) {
        if !ver.is_empty()
            && ver != REVISION_2026_07_28
            && ver != REVISION_2025_11_25
            && ver != REVISION_2025_06_18
        {
            return Some(HttpResponse::json(
                400,
                encode_error(
                    id,
                    CODE_UNSUPPORTED_PROTOCOL_VERSION,
                    "unsupported MCP-Protocol-Version",
                    None,
                ),
            ));
        }
    }
    if let Some(hdr_method) = req.header(HEADER_METHOD).map(str::trim) {
        if !hdr_method.is_empty() && hdr_method != parsed.method {
            return Some(HttpResponse::json(
                400,
                encode_error(
                    id,
                    CODE_HEADER_MISMATCH,
                    "HeaderMismatch: MCP-Method disagrees with JSON-RPC method",
                    None,
                ),
            ));
        }
    }
    None
}

fn read_http1_request<R: Read>(stream: &mut R) -> io::Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut headers = BTreeMap::new();
    let mut content_len = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("Content-Length") {
                content_len = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }
    let mut body = vec![0u8; content_len];
    reader.read_exact(&mut body)?;
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_http1_response<W: Write>(stream: &mut W, resp: &HttpResponse) -> io::Result<()> {
    let reason = match resp.status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Status",
    };
    write!(stream, "HTTP/1.1 {} {}\r\n", resp.status, reason)?;
    for (k, v) in &resp.headers {
        write!(stream, "{k}: {v}\r\n")?;
    }
    write!(stream, "Content-Length: {}\r\n\r\n", resp.body.len())?;
    stream.write_all(&resp.body)?;
    stream.flush()
}

/// Pluggable HTTP round-tripper used by [`HttpTransport`].
pub trait HttpRoundTripper {
    /// Executes an [`HttpRequest`] and returns the [`HttpResponse`].
    fn round_trip(&mut self, req: HttpRequest) -> Result<HttpResponse, SdkError>;
}

impl HttpRoundTripper for &mut HttpServerHandler<'_> {
    fn round_trip(&mut self, req: HttpRequest) -> Result<HttpResponse, SdkError> {
        Ok(self.handle(&req))
    }
}

impl<F> HttpRoundTripper for F
where
    F: FnMut(HttpRequest) -> Result<HttpResponse, SdkError>,
{
    fn round_trip(&mut self, req: HttpRequest) -> Result<HttpResponse, SdkError> {
        self(req)
    }
}

/// Client Streamable HTTP transport implementing [`Transport`].
pub struct HttpTransport<R> {
    endpoint: String,
    round_tripper: R,
    bearer_token: Option<String>,
    session_id: Option<String>,
    stateless_revision: Option<String>,
}

impl<R: HttpRoundTripper> HttpTransport<R> {
    /// Creates a client `HttpTransport` posting to `endpoint` via `round_tripper`.
    pub fn new(endpoint: impl Into<String>, round_tripper: R) -> Self {
        Self {
            endpoint: endpoint.into(),
            round_tripper,
            bearer_token: None,
            session_id: None,
            stateless_revision: None,
        }
    }

    /// Attaches `Authorization: Bearer <token>` to outgoing HTTP requests.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Seeds the initial `Mcp-Session-Id` header sent on HTTP requests.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Mirrors `MCP-Protocol-Version` and `MCP-Method` onto outgoing requests.
    pub fn with_stateless_headers(mut self, revision: impl Into<String>) -> Self {
        self.stateless_revision = Some(revision.into());
        self
    }

    /// Returns the active `Mcp-Session-Id` header value, if any.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

impl<R: HttpRoundTripper> Transport for HttpTransport<R> {
    fn send_json(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SdkError> {
        let mut req = HttpRequest::post(&self.endpoint, payload.to_vec())
            .with_header("Content-Type", "application/json")
            .with_header("Accept", "application/json, text/event-stream");
        if let Some(tok) = &self.bearer_token {
            req.headers
                .insert("Authorization".to_string(), format!("Bearer {tok}"));
        }
        if let Some(sid) = &self.session_id {
            req.headers
                .insert(HEADER_SESSION_ID.to_string(), sid.clone());
        }
        if let Some(rev) = &self.stateless_revision {
            req.headers
                .insert(HEADER_PROTOCOL_VERSION.to_string(), rev.clone());
            if let Some(method) = extract_json_method(payload) {
                req.headers.insert(HEADER_METHOD.to_string(), method);
            }
        }
        let resp = self.round_tripper.round_trip(req)?;
        if let Some(sid) = resp.header(HEADER_SESSION_ID).filter(|s| !s.is_empty()) {
            self.session_id = Some(sid.to_string());
        }
        decode_http_response(resp)
    }
}

impl<R: HttpRoundTripper> Transport for &mut HttpTransport<R> {
    fn send_json(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SdkError> {
        (**self).send_json(payload)
    }
}

fn extract_json_method(raw: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Peek {
        #[serde(default)]
        method: String,
    }
    serde_json::from_slice::<Peek>(raw)
        .ok()
        .filter(|p| !p.method.is_empty())
        .map(|p| p.method)
}

fn decode_http_response(resp: HttpResponse) -> Result<Option<Vec<u8>>, SdkError> {
    match resp.status {
        202 => Ok(None),
        200 => Ok(Some(resp.body)),
        400 | 404
            if resp
                .header("Content-Type")
                .is_some_and(|ct| ct.starts_with("application/json"))
                && !resp.body.is_empty() =>
        {
            Ok(Some(resp.body))
        }
        status => Err(SdkError::Http {
            status,
            www_authenticate: resp.header("WWW-Authenticate").map(str::to_string),
        }),
    }
}
