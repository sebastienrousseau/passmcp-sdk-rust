// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hasher};
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::SdkError;

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static ENTROPY_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a 43-character URL-safe base64url (no padding) RFC 7636 PKCE
/// `code_verifier` from 256 bits of OS randomness (`/dev/urandom` on Unix, or
/// OS-seeded `RandomState` + SHA-256 fallback).
pub fn generate_verifier() -> Result<String, SdkError> {
    let mut seed = [0u8; 32];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        if file.read_exact(&mut seed).is_ok() {
            return Ok(generate_verifier_from_seed(&seed));
        }
    }
    seed = fallback_os_seed();
    Ok(generate_verifier_from_seed(&seed))
}

/// Deterministically formats a 32-byte seed as a 43-character RFC 7636
/// base64url-nopad `code_verifier`.
pub fn generate_verifier_from_seed(seed: &[u8; 32]) -> String {
    base64url_nopad(seed)
}

fn fallback_os_seed() -> [u8; 32] {
    let mut hasher = Sha256::new();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        ENTROPY_COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .to_le_bytes(),
    );
    for i in 0..4u64 {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(i);
        hasher.update(h.finish().to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Validates `verifier` per RFC 7636 §4.1 (`43..=128` unreserved ASCII chars)
/// and returns `BASE64URL-NOPAD(SHA256(ASCII(verifier)))`.
pub fn compute_s256_challenge(verifier: &str) -> Result<String, SdkError> {
    validate_verifier(verifier)?;
    let digest = Sha256::digest(verifier.as_bytes());
    Ok(base64url_nopad(&digest))
}

/// Verifies `verifier` against an S256 `challenge` in constant time.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    if challenge.is_empty() {
        return false;
    }
    let Ok(expected) = compute_s256_challenge(verifier) else {
        return false;
    };
    constant_time_eq(expected.as_bytes(), challenge.as_bytes())
}

fn validate_verifier(verifier: &str) -> Result<(), SdkError> {
    let len = verifier.len();
    if !(43..=128).contains(&len) {
        return Err(SdkError::OAuth(format!(
            "PKCE code_verifier length {len} outside [43, 128]"
        )));
    }
    if !verifier.bytes().all(is_unreserved_char) {
        return Err(SdkError::OAuth(
            "PKCE code_verifier contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

fn is_unreserved_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn base64url_nopad(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32);
        out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 6) & 0x3f) as usize] as char);
        out.push(B64URL[(n & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    if rem.len() == 1 {
        let n = (rem[0] as u32) << 16;
        out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
    } else if rem.len() == 2 {
        let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
        out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 6) & 0x3f) as usize] as char);
    }
    out
}

/// Parameters carried on an HTTP `WWW-Authenticate: Bearer` challenge header
/// (RFC 6750 / RFC 9728).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BearerChallenge {
    /// RFC 9728 `resource_metadata` URL parameter.
    pub resource_metadata: Option<String>,
    /// Optional space-delimited `scope` parameter.
    pub scope: Option<String>,
    /// Optional OAuth error code (`invalid_token`, `insufficient_scope`, ...).
    pub error: Option<String>,
    /// Optional human-readable error description.
    pub error_description: Option<String>,
}

impl BearerChallenge {
    /// Formats a `WWW-Authenticate` header value.
    pub fn header_value(&self) -> String {
        let mut parts = Vec::new();
        push_param(&mut parts, "resource_metadata", &self.resource_metadata);
        push_param(&mut parts, "scope", &self.scope);
        push_param(&mut parts, "error", &self.error);
        push_param(&mut parts, "error_description", &self.error_description);
        if parts.is_empty() {
            "Bearer".to_string()
        } else {
            format!("Bearer {}", parts.join(", "))
        }
    }

    /// Parses a `WWW-Authenticate` Bearer challenge header value.
    pub fn parse(header: &str) -> Result<Self, SdkError> {
        let trimmed = header.trim();
        if trimmed.is_empty() {
            return Err(SdkError::OAuth("empty WWW-Authenticate header".to_string()));
        }
        if trimmed.eq_ignore_ascii_case("Bearer") {
            return Ok(Self::default());
        }
        if trimmed.len() < 7 || !trimmed[..7].eq_ignore_ascii_case("Bearer ") {
            return Err(SdkError::OAuth(
                "WWW-Authenticate scheme is not Bearer".to_string(),
            ));
        }
        let params = parse_auth_params(trimmed[7..].trim())?;
        Ok(Self {
            resource_metadata: params.get("resource_metadata").cloned(),
            scope: params.get("scope").cloned(),
            error: params.get("error").cloned(),
            error_description: params.get("error_description").cloned(),
        })
    }
}

fn push_param(parts: &mut Vec<String>, key: &str, value: &Option<String>) {
    if let Some(v) = value.as_deref().filter(|s| !s.is_empty()) {
        let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
        parts.push(format!("{key}=\"{escaped}\""));
    }
}

fn parse_auth_params(mut rest: &str) -> Result<BTreeMap<String, String>, SdkError> {
    let mut out = BTreeMap::new();
    while !rest.is_empty() {
        rest = rest.trim_start_matches([' ', '\t', ',']);
        if rest.is_empty() {
            break;
        }
        let Some((raw_key, after_eq)) = rest.split_once('=') else {
            return Err(SdkError::OAuth(format!(
                "missing '=' in WWW-Authenticate parameter {rest:?}"
            )));
        };
        let key = raw_key.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(SdkError::OAuth("empty parameter key".to_string()));
        }
        let (val, tail) = consume_param_value(after_eq.trim_start())?;
        out.insert(key, val);
        rest = tail;
    }
    Ok(out)
}

fn consume_param_value(s: &str) -> Result<(String, &str), SdkError> {
    if s.is_empty() {
        return Err(SdkError::OAuth("empty parameter value".to_string()));
    }
    if !s.starts_with('"') {
        return match s.split_once(',') {
            Some((val, tail)) => Ok((val.trim().to_string(), tail)),
            None => Ok((s.trim().to_string(), "")),
        };
    }
    let mut out = String::new();
    let mut chars = s[1..].char_indices();
    while let Some((idx, ch)) = chars.next() {
        if ch == '\\' {
            let (_, escaped) = chars
                .next()
                .ok_or_else(|| SdkError::OAuth("dangling escape in challenge".to_string()))?;
            out.push(escaped);
        } else if ch == '"' {
            return Ok((out, &s[1 + idx + 1..]));
        } else {
            out.push(ch);
        }
    }
    Err(SdkError::OAuth(
        "unterminated quoted string in WWW-Authenticate".to_string(),
    ))
}

/// RFC 9728 OAuth 2.0 Protected Resource Metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// Canonical protected resource identifier URI.
    pub resource: String,
    /// Authorization server issuer URLs trusted for this resource.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// Optional OAuth scopes supported by this resource.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    /// Derives the RFC 9728 §3.1 `(path_suffixed_url, root_url)` well-known
    /// discovery URLs for `endpoint`.
    pub fn well_known_urls(endpoint: &str) -> Result<(String, String), SdkError> {
        let parts = parse_url_parts(endpoint, true)?;
        let root = format!(
            "{}://{}/.well-known/oauth-protected-resource",
            parts.scheme, parts.host
        );
        let path_url = if parts.path.is_empty() {
            root.clone()
        } else {
            format!("{root}{}", parts.path)
        };
        Ok((path_url, root))
    }

    /// Validates that `self.resource` canonically matches `expected_endpoint`
    /// and lists at least one authorization server (RFC 9728 §3.3).
    pub fn validate_resource_binding(&self, expected_endpoint: &str) -> Result<(), SdkError> {
        let got = canonical_resource_uri(&self.resource)?;
        let want = canonical_resource_uri(expected_endpoint)?;
        if got != want {
            return Err(SdkError::OAuth(format!(
                "protected resource metadata {got:?} != expected {want:?}"
            )));
        }
        if self.authorization_servers.is_empty() {
            return Err(SdkError::OAuth(
                "protected resource metadata authorization_servers is empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// RFC 8414 OAuth 2.0 Authorization Server Metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// HTTPS authorization server issuer identifier.
    pub issuer: String,
    /// OAuth 2.1 authorization endpoint URL.
    pub authorization_endpoint: String,
    /// OAuth 2.1 token endpoint URL.
    pub token_endpoint: String,
    /// Optional RFC 7591 dynamic client registration endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// Supported PKCE code challenge methods (must include `"S256"`).
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

impl AuthorizationServerMetadata {
    /// Derives the RFC 8414 §3 well-known metadata URL for an HTTPS `issuer`.
    pub fn well_known_url(issuer: &str) -> Result<String, SdkError> {
        let parts = parse_url_parts(issuer, false)?;
        Ok(format!(
            "https://{}/.well-known/oauth-authorization-server{}",
            parts.host, parts.path
        ))
    }

    /// Enforces OAuth 2.1 server metadata invariants: HTTPS `issuer`, matching
    /// `expected_issuer` (when supplied), valid `authorization_endpoint` and
    /// `token_endpoint`, and `"S256"` in `code_challenge_methods_supported`.
    pub fn validate_oauth21(&self, expected_issuer: Option<&str>) -> Result<(), SdkError> {
        let iss = parse_url_parts(&self.issuer, false)?;
        if let Some(exp) = expected_issuer {
            let want = parse_url_parts(exp, false)?;
            if (iss.host, iss.path) != (want.host, want.path) {
                return Err(SdkError::OAuth(format!(
                    "issuer {:?} does not match expected {:?}",
                    self.issuer, exp
                )));
            }
        }
        let _ = parse_url_parts(&self.authorization_endpoint, true)?;
        let _ = parse_url_parts(&self.token_endpoint, true)?;
        if !self
            .code_challenge_methods_supported
            .iter()
            .any(|m| m == "S256")
        {
            return Err(SdkError::OAuth(
                "code_challenge_methods_supported must contain \"S256\"".to_string(),
            ));
        }
        Ok(())
    }
}

struct UrlParts {
    scheme: String,
    host: String,
    path: String,
}

fn canonical_resource_uri(raw: &str) -> Result<String, SdkError> {
    let parts = parse_url_parts(raw, true)?;
    Ok(format!("{}://{}{}", parts.scheme, parts.host, parts.path))
}

fn parse_url_parts(raw: &str, allow_loopback_http: bool) -> Result<UrlParts, SdkError> {
    let trimmed = raw.trim();
    if trimmed.contains(['?', '#']) {
        return Err(SdkError::OAuth(format!(
            "query and fragment forbidden in metadata URL {raw:?}"
        )));
    }
    let (scheme_raw, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| SdkError::OAuth(format!("malformed URL {raw:?}")))?;
    let scheme = scheme_raw.to_ascii_lowercase();
    let (host_raw, path_raw) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    if host_raw.is_empty() || host_raw.contains('@') {
        return Err(SdkError::OAuth(format!("invalid host in URL {raw:?}")));
    }
    let host = host_raw.to_ascii_lowercase();
    let host_only = host
        .strip_prefix('[')
        .and_then(|s| s.split_once(']').map(|(h, _)| h))
        .unwrap_or_else(|| host.split(':').next().unwrap_or(&host));
    let is_loopback = matches!(host_only, "localhost" | "127.0.0.1" | "::1");
    if scheme != "https" && !(allow_loopback_http && scheme == "http" && is_loopback) {
        return Err(SdkError::OAuth(format!("HTTPS URL required, got {raw:?}")));
    }
    let path = path_raw.trim_end_matches('/').to_string();
    Ok(UrlParts { scheme, host, path })
}
