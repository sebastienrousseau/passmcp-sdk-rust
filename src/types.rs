// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

pub use crate::error::{RpcError, SdkError};

/// Latest supported MCP protocol revision (`2026-07-28`).
pub const REVISION_2026_07_28: &str = "2026-07-28";
/// MCP `2025-11-25` protocol revision.
pub const REVISION_2025_11_25: &str = "2025-11-25";
/// MCP `2025-06-18` protocol revision.
pub const REVISION_2025_06_18: &str = "2025-06-18";

/// SEP-2549 public cache scope.
pub const CACHE_SCOPE_PUBLIC: &str = "public";
/// SEP-2549 private cache scope.
pub const CACHE_SCOPE_PRIVATE: &str = "private";
/// Stateless `2026-07-28` `_meta` key carrying `serverInfo`.
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// JSON-RPC 2.0 parse error code.
pub const CODE_PARSE_ERROR: i32 = -32700;
/// JSON-RPC 2.0 invalid request error code.
pub const CODE_INVALID_REQUEST: i32 = -32600;
/// JSON-RPC 2.0 method not found error code.
pub const CODE_METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC 2.0 invalid params error code (also SEP-2164 unknown resource on `2026-07-28`).
pub const CODE_INVALID_PARAMS: i32 = -32602;
/// JSON-RPC 2.0 internal error code.
pub const CODE_INTERNAL_ERROR: i32 = -32603;
/// Pre-`2026-07-28` MCP resource-not-found error code.
pub const CODE_RESOURCE_NOT_FOUND_LEGACY: i32 = -32002;
/// Stateless `2026-07-28` HTTP `MCP-Method` header mismatch error code.
pub const CODE_HEADER_MISMATCH: i32 = -32020;
/// Stateless `2026-07-28` unsupported `MCP-Protocol-Version` header error code.
pub const CODE_UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;

/// Alias for JSON object maps passed to tool handlers.
pub type JsonObject = Map<String, Value>;
/// Convenience map type for prompt arguments.
pub type PromptArgs = BTreeMap<String, String>;

/// Identity metadata for an MCP server or client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Implementation name.
    pub name: String,
    /// Implementation version string.
    pub version: String,
}

/// SEP-2549 list cache metadata emitted on `2026-07-28` list responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheHints {
    /// Non-negative cache time-to-live in milliseconds.
    pub ttl_ms: i64,
    /// Cache visibility scope (`"public"` or `"private"`).
    pub cache_scope: String,
}

impl CacheHints {
    /// Constructs and validates SEP-2549 cache hints in milliseconds.
    pub fn new(ttl_ms: i64, cache_scope: impl Into<String>) -> Result<Self, SdkError> {
        let hints = Self {
            ttl_ms,
            cache_scope: cache_scope.into(),
        };
        hints.validate()?;
        Ok(hints)
    }

    /// Constructs SEP-2549 cache hints from `(cacheable, ttl_secs, scope)`.
    pub fn from_seconds(
        cacheable: bool,
        ttl_secs: i64,
        scope: impl Into<String>,
    ) -> Result<Self, SdkError> {
        if ttl_secs < 0 {
            return Err(SdkError::InvalidCacheHints(format!(
                "ttl {ttl_secs}s must be >= 0"
            )));
        }
        let ttl_ms = if cacheable { ttl_secs * 1_000 } else { 0 };
        Self::new(ttl_ms, scope)
    }

    /// Validates `ttl_ms >= 0` and `cache_scope` in `{"public", "private"}`.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.ttl_ms < 0 {
            return Err(SdkError::InvalidCacheHints(format!(
                "ttlMs {} must be >= 0",
                self.ttl_ms
            )));
        }
        if self.cache_scope != CACHE_SCOPE_PUBLIC && self.cache_scope != CACHE_SCOPE_PRIVATE {
            return Err(SdkError::InvalidCacheHints(format!(
                "cacheScope {:?} must be \"public\" or \"private\"",
                self.cache_scope
            )));
        }
        Ok(())
    }
}

/// Marker object for a declared MCP capability group.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    /// Whether the server emits list-changed notifications for this group.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub list_changed: bool,
}

/// Server capabilities derived strictly from registered handlers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Present only when at least one tool handler is registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Capability>,
    /// Present only when at least one resource or template handler is registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Capability>,
    /// Present only when at least one prompt handler is registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<Capability>,
}

/// Optional MCP tool behaviour hints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    /// Human-readable title hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Explicit read-only guarantee (`true` permits default client execution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    /// Explicit destructive hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    /// Explicit idempotency hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    /// Explicit open-world network hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

fn default_object_schema() -> Value {
    json!({"type": "object"})
}

/// Descriptor for one callable MCP tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    /// Unique tool identifier.
    pub name: String,
    /// Optional human-readable display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Human/model description of what the tool does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for arguments (defaults to `{"type": "object"}`).
    #[serde(default = "default_object_schema")]
    pub input_schema: Value,
    /// Optional JSON Schema describing `structuredContent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Optional MCP tool annotations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

impl Tool {
    /// Constructs an unannotated tool (treated as mutating by default client policy).
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            title: None,
            description: Some(description.into()),
            input_schema: default_object_schema(),
            output_schema: None,
            annotations: None,
        }
    }

    /// Constructs a read-only tool (`annotations.readOnlyHint = true`).
    pub fn read_only(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            title: None,
            description: Some(description.into()),
            input_schema: default_object_schema(),
            output_schema: None,
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(true),
                ..ToolAnnotations::default()
            }),
        }
    }

    /// Reports whether the tool explicitly declares `annotations.readOnlyHint == true`.
    pub fn is_read_only(&self) -> bool {
        self.annotations
            .as_ref()
            .and_then(|a| a.read_only_hint)
            .unwrap_or(false)
    }
}

/// Single content item returned by a tool or prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentBlock {
    /// Content kind (for example `"text"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Text body when `kind == "text"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Optional MIME type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl ContentBlock {
    /// Constructs a plain text content block.
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            kind: "text".to_string(),
            text: Some(value.into()),
            mime_type: None,
        }
    }
}

/// Response payload of `tools/call`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    /// Returned content blocks.
    pub content: Vec<ContentBlock>,
    /// Whether the tool reported an application-level execution error.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
    /// Optional structured JSON matching `outputSchema`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
}

impl CallToolResult {
    /// Constructs a successful single-text tool result.
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::text(value)],
            is_error: false,
            structured_content: None,
        }
    }

    /// Constructs a successful tool result carrying both text and `structuredContent`.
    pub fn structured(text: impl Into<String>, structured: Value) -> Self {
        Self {
            content: vec![ContentBlock::text(text)],
            is_error: false,
            structured_content: Some(structured),
        }
    }

    /// Constructs an error single-text tool result (`isError: true`).
    pub fn error(value: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::text(value)],
            is_error: true,
            structured_content: None,
        }
    }
}

impl From<String> for CallToolResult {
    fn from(value: String) -> Self {
        Self::text(value)
    }
}

impl From<&str> for CallToolResult {
    fn from(value: &str) -> Self {
        Self::text(value)
    }
}

/// Readable static MCP resource descriptor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    /// Canonical resource URI.
    pub uri: String,
    /// Short display name.
    pub name: String,
    /// Optional human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional MIME type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Parameterized URI template descriptor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTemplate {
    /// RFC 6570 URI template.
    pub uri_template: String,
    /// Short display name.
    pub name: String,
    /// Optional human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional MIME type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Body item returned inside `resources/read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContents {
    /// Resolved resource URI.
    pub uri: String,
    /// Optional MIME type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// UTF-8 text payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Response payload of `resources/read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadResourceResult {
    /// Resource contents list.
    pub contents: Vec<ResourceContents>,
}

/// Named argument accepted by a prompt template.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name.
    pub name: String,
    /// Optional argument description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the caller must provide this argument.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
}

/// Server prompt descriptor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    /// Unique prompt name.
    pub name: String,
    /// Optional human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Declared prompt arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
}

/// Single message inside a rendered prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptMessage {
    /// Speaker role (`"user"` or `"assistant"`).
    pub role: String,
    /// Message content block.
    pub content: ContentBlock,
}

/// Response payload of `prompts/get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetPromptResult {
    /// Optional prompt description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Rendered messages.
    pub messages: Vec<PromptMessage>,
}

/// Response payload of `initialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    /// Negotiated MCP protocol revision.
    pub protocol_version: String,
    /// Declared server capabilities.
    pub capabilities: Capabilities,
    /// Server identity.
    pub server_info: ServerInfo,
    /// Optional server instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

/// Stateless `2026-07-28` `_meta` payload carried on `server/discover`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverMeta {
    /// Server identity under `io.modelcontextprotocol/serverInfo`.
    #[serde(
        rename = "io.modelcontextprotocol/serverInfo",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub server_info: Option<ServerInfo>,
    /// SEP-2549 cache time-to-live in milliseconds.
    pub ttl_ms: i64,
    /// SEP-2549 cache visibility scope.
    pub cache_scope: String,
}

/// Response payload of stateless `server/discover`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverResult {
    /// Stateless result discriminator (`"discover"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_type: Option<String>,
    /// Server protocol revision.
    pub protocol_version: String,
    /// Supported MCP revisions advertised by the server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_versions: Vec<String>,
    /// Server identity.
    pub server_info: ServerInfo,
    /// Derived capabilities.
    pub capabilities: Capabilities,
    /// Optional server instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Registered tools when `capabilities.tools` is declared.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Tool>,
    /// Registered resources when `capabilities.resources` is declared.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<Resource>,
    /// Registered resource templates when present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_templates: Vec<ResourceTemplate>,
    /// Registered prompts when `capabilities.prompts` is declared.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompts: Vec<Prompt>,
    /// Stateless `_meta` carrying `io.modelcontextprotocol/serverInfo` and SEP-2549 hints.
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<DiscoverMeta>,
}
