// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

/// Strict HTTP `Origin` header allowlist guard preventing cross-origin and
/// DNS-rebinding requests against MCP HTTP transports.
#[derive(Debug, Clone, Default)]
pub struct OriginGuard {
    allowed: BTreeSet<String>,
}

impl OriginGuard {
    /// Creates an `OriginGuard` permitting only exact normalized `scheme://host[:port]`
    /// entries. Wildcards (`"*"`) and `"null"` are ignored so a guard never fails open.
    pub fn new<I, S>(origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allowed = origins
            .into_iter()
            .filter_map(|raw| normalize_origin(raw.as_ref()))
            .collect();
        Self { allowed }
    }

    /// Reports whether `origin` is permitted. `None` or `Some("")` (requests
    /// without an HTTP `Origin` header) are permitted; any non-empty `Origin`
    /// must match an allowlisted origin.
    pub fn is_allowed(&self, origin: Option<&str>) -> bool {
        match origin {
            None | Some("") => true,
            Some(raw) => normalize_origin(raw)
                .map(|norm| self.allowed.contains(&norm))
                .unwrap_or(false),
        }
    }
}

fn normalize_origin(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.eq_ignore_ascii_case("null") {
        return None;
    }
    let (scheme, rest) = trimmed.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-')
    {
        return None;
    }
    let host = rest.strip_suffix('/').unwrap_or(rest);
    if host.is_empty() || host.contains(['/', '?', '#', '@']) {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase()
    ))
}
