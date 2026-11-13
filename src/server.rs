// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use crate::origin::OriginGuard;
use crate::schema::{validate_prompt_args, validate_tool_args};
use crate::types::{
    CacheHints, CallToolResult, Capabilities, Capability, DiscoverMeta, DiscoverResult,
    GetPromptResult, InitializeResult, JsonObject, Prompt, PromptArgs, ReadResourceResult,
    Resource, ResourceContents, ResourceTemplate, RpcError, SdkError, ServerInfo, Tool,
    CACHE_SCOPE_PRIVATE, CODE_INTERNAL_ERROR, CODE_INVALID_PARAMS, CODE_INVALID_REQUEST,
    CODE_METHOD_NOT_FOUND, CODE_PARSE_ERROR, CODE_RESOURCE_NOT_FOUND_LEGACY, REVISION_2025_06_18,
    REVISION_2025_11_25, REVISION_2026_07_28,
};

type BoxToolHandler = Box<dyn Fn(&JsonObject) -> Result<CallToolResult, RpcError> + Send + Sync>;
type BoxResourceHandler = Box<dyn Fn(&str) -> Result<ResourceContents, String> + Send + Sync>;
type BoxPromptHandler = Box<dyn Fn(&PromptArgs) -> Result<GetPromptResult, String> + Send + Sync>;

#[derive(Deserialize)]
pub(crate) struct RpcRequest {
    #[serde(default)]
    pub(crate) jsonrpc: String,
    pub(crate) id: Option<Value>,
    #[serde(default)]
    pub(crate) method: String,
    #[serde(default)]
    pub(crate) params: Value,
}

/// Capability-derived MCP JSON-RPC 2.0 server.
pub struct McpServer {
    info: ServerInfo,
    revision: String,
    instructions: Option<String>,
    cache_hints: CacheHints,
    origin_guard: OriginGuard,
    tools: Vec<(Tool, BoxToolHandler)>,
    resources: Vec<(Resource, BoxResourceHandler)>,
    templates: Vec<(ResourceTemplate, BoxResourceHandler)>,
    prompts: Vec<(Prompt, BoxPromptHandler)>,
}

impl McpServer {
    /// Creates a new `McpServer` defaulting to revision `2026-07-28`,
    /// private zero-TTL SEP-2549 cache hints, and a strict empty `OriginGuard`.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            info: ServerInfo {
                name: name.into(),
                version: version.into(),
            },
            revision: REVISION_2026_07_28.to_string(),
            instructions: None,
            cache_hints: CacheHints {
                ttl_ms: 0,
                cache_scope: CACHE_SCOPE_PRIVATE.to_string(),
            },
            origin_guard: OriginGuard::default(),
            tools: Vec::new(),
            resources: Vec::new(),
            templates: Vec::new(),
            prompts: Vec::new(),
        }
    }

    /// Sets the server's negotiated MCP protocol revision.
    pub fn with_revision(mut self, revision: impl Into<String>) -> Self {
        let rev = revision.into();
        if !rev.trim().is_empty() {
            self.revision = rev;
        }
        self
    }

    /// Sets optional server instructions included in `initialize` and `server/discover`.
    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// Configures the server's HTTP `OriginGuard` allowlist.
    pub fn with_allowed_origins<I, S>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.origin_guard = OriginGuard::new(origins);
        self
    }

    /// Validates and updates the server's SEP-2549 cache hints.
    pub fn set_cache_hints(&mut self, hints: CacheHints) -> Result<(), SdkError> {
        hints.validate()?;
        self.cache_hints = hints;
        Ok(())
    }

    /// Sets SEP-2549 cache hints directly (validated on every list emission).
    pub fn with_cache_hints(mut self, hints: CacheHints) -> Self {
        self.cache_hints = hints;
        self
    }

    /// Returns the server's identity metadata.
    pub fn info(&self) -> &ServerInfo {
        &self.info
    }

    /// Returns the server's configured MCP protocol revision.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Returns the server's `OriginGuard`.
    pub fn origin_guard(&self) -> &OriginGuard {
        &self.origin_guard
    }

    /// Derives `Capabilities` strictly from registered handlers.
    pub fn capabilities(&self) -> Capabilities {
        Capabilities {
            tools: (!self.tools.is_empty()).then(Capability::default),
            resources: (!self.resources.is_empty() || !self.templates.is_empty())
                .then(Capability::default),
            prompts: (!self.prompts.is_empty()).then(Capability::default),
        }
    }

    /// Registers a tool whose string errors map to `CallToolResult { isError: true }`.
    pub fn register_tool<F, R>(&mut self, tool: Tool, handler: F)
    where
        F: Fn(&JsonObject) -> Result<R, String> + Send + Sync + 'static,
        R: Into<CallToolResult>,
    {
        self.register_checked_tool(tool, move |args| {
            Ok(handler(args)
                .map(Into::into)
                .unwrap_or_else(CallToolResult::error))
        });
    }

    /// Registers a tool that may return protocol-level [`RpcError`]s (such as `-32602`).
    pub fn register_checked_tool<F>(&mut self, tool: Tool, handler: F)
    where
        F: Fn(&JsonObject) -> Result<CallToolResult, RpcError> + Send + Sync + 'static,
    {
        let boxed: BoxToolHandler = Box::new(handler);
        if let Some(slot) = self.tools.iter_mut().find(|(t, _)| t.name == tool.name) {
            *slot = (tool, boxed);
        } else {
            self.tools.push((tool, boxed));
        }
    }

    /// Registers a static resource and enables `resources/*`.
    pub fn register_resource<F>(&mut self, resource: Resource, handler: F)
    where
        F: Fn(&str) -> Result<ResourceContents, String> + Send + Sync + 'static,
    {
        let boxed: BoxResourceHandler = Box::new(handler);
        if let Some(slot) = self
            .resources
            .iter_mut()
            .find(|(r, _)| r.uri == resource.uri)
        {
            *slot = (resource, boxed);
        } else {
            self.resources.push((resource, boxed));
        }
    }

    /// Registers a parameterized resource template and enables `resources/*`.
    pub fn register_resource_template<F>(&mut self, template: ResourceTemplate, handler: F)
    where
        F: Fn(&str) -> Result<ResourceContents, String> + Send + Sync + 'static,
    {
        self.templates.push((template, Box::new(handler)));
    }

    /// Registers a prompt template and enables `prompts/*`.
    pub fn register_prompt<F>(&mut self, prompt: Prompt, handler: F)
    where
        F: Fn(&PromptArgs) -> Result<GetPromptResult, String> + Send + Sync + 'static,
    {
        let boxed: BoxPromptHandler = Box::new(handler);
        if let Some(slot) = self.prompts.iter_mut().find(|(p, _)| p.name == prompt.name) {
            *slot = (prompt, boxed);
        } else {
            self.prompts.push((prompt, boxed));
        }
    }

    /// Dispatches a raw JSON-RPC 2.0 request. Notifications (messages without
    /// an `id`) return `None`; requests return `Some(response_bytes)`.
    pub fn handle_json(&self, raw: &[u8]) -> Option<Vec<u8>> {
        let Ok(req) = serde_json::from_slice::<RpcRequest>(raw) else {
            return Some(encode_error(
                Value::Null,
                CODE_PARSE_ERROR,
                "Parse error",
                None,
            ));
        };
        if req.jsonrpc != "2.0" || req.method.trim().is_empty() {
            let id = req.id.unwrap_or(Value::Null);
            return Some(encode_error(
                id,
                CODE_INVALID_REQUEST,
                "invalid JSON-RPC 2.0 request",
                None,
            ));
        }
        let id = req.id?;
        match self.dispatch(&req.method, &req.params) {
            Ok(res) => serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": res})).ok(),
            Err(err) => Some(encode_error(id, err.code, &err.message, err.data)),
        }
    }

    fn dispatch(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        match method {
            "initialize" => to_json_value(InitializeResult {
                protocol_version: self.revision.clone(),
                capabilities: self.capabilities(),
                server_info: self.info.clone(),
                instructions: self.instructions.clone(),
            }),
            "notifications/initialized" | "notifications/cancelled" | "ping" => Ok(json!({})),
            "server/discover" => self.handle_discover(),
            _ => self.dispatch_catalog(method, params),
        }
    }

    fn dispatch_catalog(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        let has_res = !self.resources.is_empty() || !self.templates.is_empty();
        match method {
            "tools/list" => {
                self.list_response(!self.tools.is_empty(), "tools", firsts(&self.tools))
            }
            "tools/call" => self.handle_tools_call(params),
            "resources/list" => self.list_response(has_res, "resources", firsts(&self.resources)),
            "resources/templates/list" => {
                self.list_response(has_res, "resourceTemplates", firsts(&self.templates))
            }
            "resources/read" => self.handle_resources_read(params),
            "prompts/list" => {
                self.list_response(!self.prompts.is_empty(), "prompts", firsts(&self.prompts))
            }
            "prompts/get" => self.handle_prompts_get(params),
            _ => Err(rpc_err(
                CODE_METHOD_NOT_FOUND,
                format!("method not found: {method}"),
            )),
        }
    }

    fn list_meta(&self) -> Result<Option<CacheHints>, RpcError> {
        if self.revision != REVISION_2026_07_28 {
            return Ok(None);
        }
        self.cache_hints
            .validate()
            .map_err(|e| rpc_err(CODE_INTERNAL_ERROR, e.to_string()))?;
        Ok(Some(self.cache_hints.clone()))
    }

    fn list_response<T: Serialize>(
        &self,
        enabled: bool,
        key: &str,
        items: Vec<T>,
    ) -> Result<Value, RpcError> {
        if !enabled {
            return Err(rpc_err(
                CODE_METHOD_NOT_FOUND,
                format!("capability not declared: {key}"),
            ));
        }
        let mut map = serde_json::Map::new();
        map.insert(key.to_string(), to_json_value(items)?);
        if let Some(hints) = self.list_meta()? {
            map.insert("resultType".to_string(), json!("complete"));
            map.insert("ttlMs".to_string(), json!(hints.ttl_ms));
            map.insert("cacheScope".to_string(), json!(hints.cache_scope));
            map.insert("_meta".to_string(), to_json_value(hints)?);
        }
        Ok(Value::Object(map))
    }

    fn handle_discover(&self) -> Result<Value, RpcError> {
        if self.revision != REVISION_2026_07_28 {
            return Err(rpc_err(
                CODE_METHOD_NOT_FOUND,
                "method not found: server/discover",
            ));
        }
        let meta = self.list_meta()?.map(|hints| DiscoverMeta {
            server_info: Some(self.info.clone()),
            ttl_ms: hints.ttl_ms,
            cache_scope: hints.cache_scope,
        });
        to_json_value(DiscoverResult {
            result_type: Some("discover".to_string()),
            protocol_version: self.revision.clone(),
            supported_versions: vec![
                REVISION_2026_07_28.to_string(),
                REVISION_2025_11_25.to_string(),
                REVISION_2025_06_18.to_string(),
            ],
            server_info: self.info.clone(),
            capabilities: self.capabilities(),
            instructions: self.instructions.clone(),
            tools: firsts(&self.tools),
            resources: firsts(&self.resources),
            resource_templates: firsts(&self.templates),
            prompts: firsts(&self.prompts),
            meta,
        })
    }

    fn handle_tools_call(&self, params: &Value) -> Result<Value, RpcError> {
        if self.tools.is_empty() {
            return Err(rpc_err(
                CODE_METHOD_NOT_FOUND,
                "capability not declared: tools",
            ));
        }
        let name = required_str(params, "name", "invalid tools/call params")?;
        let empty = JsonObject::new();
        let args = params
            .get("arguments")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        let (tool, handler) = self
            .tools
            .iter()
            .find(|(t, _)| t.name == name)
            .ok_or_else(|| rpc_err(CODE_INVALID_PARAMS, format!("unknown tool: {name}")))?;
        validate_tool_args(&tool.input_schema, args)?;
        to_json_value(handler(args)?)
    }

    fn handle_resources_read(&self, params: &Value) -> Result<Value, RpcError> {
        if self.resources.is_empty() && self.templates.is_empty() {
            return Err(rpc_err(
                CODE_METHOD_NOT_FOUND,
                "capability not declared: resources",
            ));
        }
        let uri = required_str(params, "uri", "invalid resources/read params")?;
        let Some(handler) = self.lookup_resource_handler(uri) else {
            return Err(missing_resource_error(&self.revision, uri));
        };
        let contents = handler(uri).map_err(|msg| rpc_err(CODE_INTERNAL_ERROR, msg))?;
        to_json_value(ReadResourceResult {
            contents: vec![contents],
        })
    }

    fn lookup_resource_handler(&self, uri: &str) -> Option<&BoxResourceHandler> {
        if let Some((_, handler)) = self.resources.iter().find(|(r, _)| r.uri == uri) {
            return Some(handler);
        }
        self.templates
            .iter()
            .find(|(t, _)| matches_template_prefix(&t.uri_template, uri))
            .map(|(_, h)| h)
    }

    fn handle_prompts_get(&self, params: &Value) -> Result<Value, RpcError> {
        if self.prompts.is_empty() {
            return Err(rpc_err(
                CODE_METHOD_NOT_FOUND,
                "capability not declared: prompts",
            ));
        }
        let name = required_str(params, "name", "invalid prompts/get params")?;
        let args = extract_prompt_args(params.get("arguments"));
        let (prompt, handler) = self
            .prompts
            .iter()
            .find(|(p, _)| p.name == name)
            .ok_or_else(|| rpc_err(CODE_INVALID_PARAMS, format!("unknown prompt: {name}")))?;
        validate_prompt_args(&prompt.arguments, &args)?;
        let out = handler(&args).map_err(|msg| rpc_err(CODE_INTERNAL_ERROR, msg))?;
        to_json_value(out)
    }
}

fn firsts<A: Clone, B>(items: &[(A, B)]) -> Vec<A> {
    items.iter().map(|(a, _)| a.clone()).collect()
}

fn required_str<'a>(params: &'a Value, key: &str, err_msg: &str) -> Result<&'a str, RpcError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| rpc_err(CODE_INVALID_PARAMS, err_msg))
}

fn extract_prompt_args(value: Option<&Value>) -> PromptArgs {
    let mut out = PromptArgs::new();
    if let Some(obj) = value.and_then(Value::as_object) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                out.insert(k.clone(), s.to_string());
            }
        }
    }
    out
}

fn matches_template_prefix(uri_template: &str, uri: &str) -> bool {
    match uri_template.split_once('{') {
        Some((prefix, _)) => {
            !prefix.is_empty() && uri.starts_with(prefix) && uri.len() > prefix.len()
        }
        None => uri_template == uri,
    }
}

fn missing_resource_error(revision: &str, uri: &str) -> RpcError {
    let code = if revision == REVISION_2026_07_28 {
        CODE_INVALID_PARAMS
    } else {
        CODE_RESOURCE_NOT_FOUND_LEGACY
    };
    RpcError {
        code,
        message: format!("resource {uri:?} not found; call resources/list for available URIs"),
        data: Some(json!({"uri": uri})),
    }
}

fn to_json_value<T: Serialize>(value: T) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(|e| rpc_err(CODE_INTERNAL_ERROR, e.to_string()))
}

pub(crate) fn rpc_err(code: i32, message: impl Into<String>) -> RpcError {
    RpcError {
        code,
        message: message.into(),
        data: None,
    }
}

pub(crate) fn encode_error(id: Value, code: i32, message: &str, data: Option<Value>) -> Vec<u8> {
    let err = RpcError {
        code,
        message: message.to_string(),
        data,
    };
    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "error": err})).unwrap_or_default()
}
