// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::attestation::{verify_target, AttestationError, Statement};
use crate::server::McpServer;
use crate::types::{
    CallToolResult, DiscoverResult, GetPromptResult, InitializeResult, Prompt, PromptArgs,
    ReadResourceResult, Resource, ResourceTemplate, RpcError, SdkError, ServerInfo, Tool,
    REVISION_2026_07_28,
};

/// Client tool execution safety policy.
///
/// `Policy::default()` sets `allow_mutations = false`, enforcing `passmcp`
/// ADR 0004: tools lacking `annotations.readOnlyHint == true` are refused
/// before sending `tools/call`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Whether tools without `readOnlyHint: true` may be invoked.
    pub allow_mutations: bool,
    /// Explicit tool names denied regardless of `allow_mutations`.
    pub deny: Vec<String>,
}

/// Abstract JSON-RPC 2.0 byte transport used by [`McpClient`].
pub trait Transport {
    /// Sends a single JSON-RPC 2.0 payload and returns the optional response frame.
    fn send_json(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SdkError>;
}

impl Transport for &McpServer {
    fn send_json(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SdkError> {
        Ok(self.handle_json(payload))
    }
}

impl Transport for McpServer {
    fn send_json(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SdkError> {
        Ok(self.handle_json(payload))
    }
}

impl<F> Transport for F
where
    F: FnMut(&[u8]) -> Result<Option<Vec<u8>>, SdkError>,
{
    fn send_json(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SdkError> {
        self(payload)
    }
}

struct AttestationGate {
    statement: Statement,
    transport: String,
    endpoint: String,
}

/// Policy-enforcing MCP JSON-RPC 2.0 client.
pub struct McpClient<T> {
    transport: T,
    client_info: ServerInfo,
    revision: String,
    policy: Policy,
    gate: Option<AttestationGate>,
    next_id: u64,
    tools_loaded: bool,
    tools: BTreeMap<String, Tool>,
}

impl<T: Transport> McpClient<T> {
    /// Creates a new `McpClient` with default read-only [`Policy`].
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            client_info: ServerInfo {
                name: "passmcp-sdk".to_string(),
                version: "0.0.10".to_string(),
            },
            revision: REVISION_2026_07_28.to_string(),
            policy: Policy::default(),
            gate: None,
            next_id: 0,
            tools_loaded: false,
            tools: BTreeMap::new(),
        }
    }

    /// Overrides the client's tool execution [`Policy`].
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Overrides the client identity sent during `initialize`.
    pub fn with_client_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.client_info = ServerInfo {
            name: name.into(),
            version: version.into(),
        };
        self
    }

    /// Requires a verified `passmcp` [`Statement`] covering `(transport_kind, endpoint)`
    /// before every outbound client request.
    pub fn with_required_attestation(
        mut self,
        statement: Statement,
        transport_kind: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        self.gate = Some(AttestationGate {
            statement,
            transport: transport_kind.into(),
            endpoint: endpoint.into(),
        });
        self
    }

    /// Performs `initialize` followed by `notifications/initialized`.
    pub fn connect(&mut self) -> Result<InitializeResult, SdkError> {
        let init: InitializeResult = self.call(
            "initialize",
            json!({
                "protocolVersion": self.revision,
                "capabilities": {},
                "clientInfo": self.client_info,
            }),
        )?;
        self.notify("notifications/initialized")?;
        Ok(init)
    }

    /// Calls stateless `server/discover` and caches any advertised tool descriptors.
    pub fn discover(&mut self) -> Result<DiscoverResult, SdkError> {
        let out: DiscoverResult = self.call("server/discover", json!({}))?;
        if out.capabilities.tools.is_some() {
            self.cache_tools(&out.tools);
        }
        Ok(out)
    }

    /// Sends a JSON-RPC `ping` request.
    pub fn ping(&mut self) -> Result<(), SdkError> {
        let _: Value = self.call("ping", json!({}))?;
        Ok(())
    }

    /// Fetches `tools/list` and updates the client's tool policy cache.
    pub fn list_tools(&mut self) -> Result<Vec<Tool>, SdkError> {
        #[derive(Deserialize)]
        struct Envelope {
            tools: Vec<Tool>,
        }
        let env: Envelope = self.call("tools/list", json!({}))?;
        self.cache_tools(&env.tools);
        Ok(env.tools)
    }

    /// Enforces [`Policy`] (`deny` list and `readOnlyHint: true` default) before
    /// invoking `tools/call`.
    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Result<CallToolResult, SdkError> {
        self.check_gate()?;
        if self.policy.deny.iter().any(|d| d == name) {
            return Err(SdkError::PolicyViolation(format!(
                "tool {name:?} is denied"
            )));
        }
        if !self.policy.allow_mutations {
            self.require_read_only(name)?;
        }
        let args = if arguments.is_null() {
            json!({})
        } else {
            arguments
        };
        self.call("tools/call", json!({ "name": name, "arguments": args }))
    }

    /// Fetches `resources/list`.
    pub fn list_resources(&mut self) -> Result<Vec<Resource>, SdkError> {
        #[derive(Deserialize)]
        struct Envelope {
            resources: Vec<Resource>,
        }
        let env: Envelope = self.call("resources/list", json!({}))?;
        Ok(env.resources)
    }

    /// Fetches `resources/templates/list`.
    pub fn list_resource_templates(&mut self) -> Result<Vec<ResourceTemplate>, SdkError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Envelope {
            resource_templates: Vec<ResourceTemplate>,
        }
        let env: Envelope = self.call("resources/templates/list", json!({}))?;
        Ok(env.resource_templates)
    }

    /// Reads a resource by URI (`resources/read`).
    pub fn read_resource(&mut self, uri: &str) -> Result<ReadResourceResult, SdkError> {
        self.call("resources/read", json!({ "uri": uri }))
    }

    /// Fetches `prompts/list`.
    pub fn list_prompts(&mut self) -> Result<Vec<Prompt>, SdkError> {
        #[derive(Deserialize)]
        struct Envelope {
            prompts: Vec<Prompt>,
        }
        let env: Envelope = self.call("prompts/list", json!({}))?;
        Ok(env.prompts)
    }

    /// Renders a named prompt (`prompts/get`).
    pub fn get_prompt(
        &mut self,
        name: &str,
        arguments: &PromptArgs,
    ) -> Result<GetPromptResult, SdkError> {
        self.call(
            "prompts/get",
            json!({ "name": name, "arguments": arguments }),
        )
    }

    fn cache_tools(&mut self, tools: &[Tool]) {
        self.tools = tools.iter().map(|t| (t.name.clone(), t.clone())).collect();
        self.tools_loaded = true;
    }

    fn require_read_only(&mut self, name: &str) -> Result<(), SdkError> {
        if !self.tools_loaded {
            self.list_tools()?;
        }
        match self.tools.get(name) {
            Some(tool) if tool.is_read_only() => Ok(()),
            _ => Err(SdkError::PolicyViolation(format!(
                "tool {name:?} lacks readOnlyHint: true"
            ))),
        }
    }

    fn check_gate(&self) -> Result<(), SdkError> {
        let Some(gate) = &self.gate else {
            return Ok(());
        };
        gate.statement.validate()?;
        if !gate.statement.covers(&gate.transport, &gate.endpoint) {
            return Err(SdkError::Attestation(AttestationError::TargetMismatch {
                transport: gate.transport.clone(),
                endpoint: gate.endpoint.trim().to_string(),
            }));
        }
        Ok(())
    }

    fn notify(&mut self, method: &str) -> Result<(), SdkError> {
        self.check_gate()?;
        let payload = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": method,
        }))
        .map_err(|e| SdkError::Transport(e.to_string()))?;
        let _ = self.transport.send_json(&payload)?;
        Ok(())
    }

    fn call<R: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<R, SdkError> {
        self.check_gate()?;
        self.next_id += 1;
        let payload = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params,
        }))
        .map_err(|e| SdkError::Transport(e.to_string()))?;
        let raw = self
            .transport
            .send_json(&payload)?
            .ok_or_else(|| SdkError::Transport("empty response frame".to_string()))?;
        decode_response(&raw)
    }
}

/// Parses and verifies raw attestation bytes for `(transport, endpoint)` with
/// optional minimum score and denied-failure selectors, suitable for gating
/// [`McpClient::with_required_attestation`].
pub fn verify_attestation_gate(
    bytes: &[u8],
    transport: &str,
    endpoint: &str,
    min_score: Option<f64>,
    deny_fail_in: &[&str],
) -> Result<Statement, SdkError> {
    verify_target(bytes, transport, endpoint, min_score, deny_fail_in).map_err(SdkError::from)
}

fn decode_response<R: DeserializeOwned>(raw: &[u8]) -> Result<R, SdkError> {
    #[derive(Deserialize)]
    struct Envelope {
        result: Option<Value>,
        error: Option<RpcError>,
    }
    let env: Envelope =
        serde_json::from_slice(raw).map_err(|e| SdkError::Transport(e.to_string()))?;
    if let Some(err) = env.error {
        return Err(SdkError::Rpc(err));
    }
    let result = env
        .result
        .ok_or_else(|| SdkError::Transport("response missing result and error".to_string()))?;
    serde_json::from_value(result).map_err(|e| SdkError::Transport(e.to_string()))
}
