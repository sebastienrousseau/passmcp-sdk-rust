// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Expected `in-toto` envelope URI.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// Expected `passmcp` MCP evaluation predicate URI.
pub const PREDICATE_TYPE: &str = "https://satellion.com/attestation/mcp-evaluation/v1";
/// Expected `predicate.subjectKind` discriminator for target descriptors.
pub const SUBJECT_KIND_DESCRIPTOR: &str = "mcp-target-descriptor";

/// Errors returned when parsing, validating, or gating on an attestation.
#[derive(Debug, Clone, PartialEq)]
pub enum AttestationError {
    /// Input bytes are not valid JSON for an `in-toto` statement.
    MalformedJson(String),
    /// Statement failed one or more structural or digest invariants.
    InvalidStatement(Vec<String>),
    /// Requested check ID was not recorded in `predicate.verdicts`.
    NoSuchCheck(String),
    /// Statement subject digest does not cover the requested target.
    TargetMismatch {
        /// Requested transport (`"http"` or `"stdio"`).
        transport: String,
        /// Requested trimmed endpoint.
        endpoint: String,
    },
    /// Policy failed on minimum score or denied check failure.
    PolicyRejected(String),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedJson(msg) => write!(f, "attestation: not a statement: {msg}"),
            Self::InvalidStatement(issues) => write!(f, "attestation: {}", issues.join("; ")),
            Self::NoSuchCheck(id) => {
                write!(f, "attestation: the statement carries no verdict for {id}")
            }
            Self::TargetMismatch {
                transport,
                endpoint,
            } => write!(
                f,
                "attestation: statement does not cover {transport} {endpoint}"
            ),
            Self::PolicyRejected(msg) => write!(f, "attestation: policy rejected: {msg}"),
        }
    }
}

impl std::error::Error for AttestationError {}

/// Verified `in-toto` `Statement/v1` envelope carrying an `mcp-evaluation/v1` predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    /// Envelope type URI (`https://in-toto.io/Statement/v1`).
    #[serde(rename = "_type", default)]
    pub statement_type: String,
    /// Single evaluated target subject.
    #[serde(default)]
    pub subject: Vec<Subject>,
    /// Predicate type URI (`https://satellion.com/attestation/mcp-evaluation/v1`).
    #[serde(rename = "predicateType", default)]
    pub predicate_type: String,
    /// Evaluation predicate body.
    #[serde(default)]
    pub predicate: Evaluation,
}

/// Subject entry naming the target endpoint and carrying its descriptor digests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// Target endpoint string.
    #[serde(default)]
    pub name: String,
    /// Algorithm-keyed hex digests over `transport + "\n" + trim(endpoint)`.
    #[serde(default)]
    pub digest: BTreeMap<String, String>,
}

/// `passmcp` `mcp-evaluation/v1` predicate.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evaluation {
    /// Descriptor kind (`"mcp-target-descriptor"`).
    #[serde(default)]
    pub subject_kind: String,
    /// Evaluated MCP server target.
    #[serde(default)]
    pub target: Target,
    /// Spec revision, rubric, and check inventory versions.
    #[serde(default)]
    pub judged_against: Basis,
    /// Producer tool identity.
    #[serde(default)]
    pub instrument: Instrument,
    /// RFC 3339 timestamp when the run began.
    #[serde(default)]
    pub ran_at: String,
    /// Duration string reported by the instrument.
    #[serde(default)]
    pub took: String,
    /// Every check outcome recorded during the evaluation.
    #[serde(default)]
    pub verdicts: Vec<Verdict>,
    /// Tallied counts per verdict status.
    #[serde(default)]
    pub counts: Counts,
    /// Optional rubric-backed score summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<Score>,
    /// Optional early-block reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    /// Optional telemetry trace identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Optional opaque producer measurement plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<serde_json::Value>,
}

/// Target transport and endpoint evaluated by `passmcp`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Transport kind (`"http"` or `"stdio"`).
    #[serde(default)]
    pub transport: String,
    /// Endpoint URL or command line.
    #[serde(default)]
    pub endpoint: String,
    /// Optional self-reported server identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerIdentity>,
}

/// Server-reported name, version, and negotiated protocol revision.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerIdentity {
    /// Server name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Server version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Negotiated protocol version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
}

/// Rubric and inventory versions behind the evaluation's verdicts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Basis {
    /// Negotiated MCP spec revision.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub spec_revision: String,
    /// Scoring rubric version (required whenever `score` is present).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rubric: String,
    /// Check inventory catalogue version.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub check_inventory: String,
}

/// Producer instrument metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Instrument {
    /// Producer name (for example `"passmcp"`).
    #[serde(default)]
    pub name: String,
    /// Producer version.
    #[serde(default)]
    pub version: String,
    /// Source report schema version.
    #[serde(default)]
    pub report_schema_version: i64,
}

/// Single check verdict inside an evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// Canonical check identifier (for example `"protocol.origin"`).
    #[serde(default)]
    pub id: String,
    /// Evaluation phase name.
    #[serde(default)]
    pub phase: String,
    /// Outcome (`"pass"`, `"warn"`, `"fail"`, `"skip"`, or `"info"`).
    #[serde(default)]
    pub status: String,
    /// Optional failure/warning severity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Recorded request references supporting the verdict.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Optional inventory documentation URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// Tallied verdict totals by status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    /// Number of `"pass"` verdicts.
    #[serde(default)]
    pub pass: usize,
    /// Number of `"warn"` verdicts.
    #[serde(default)]
    pub warn: usize,
    /// Number of `"fail"` verdicts.
    #[serde(default)]
    pub fail: usize,
    /// Number of `"skip"` verdicts.
    #[serde(default)]
    pub skip: usize,
    /// Number of `"info"` verdicts.
    #[serde(default)]
    pub info: usize,
}

/// Rubric-backed overall score and grade.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Score {
    /// Numeric score `[0, 100]`.
    pub total: f64,
    /// Letter grade.
    pub grade: String,
    /// Number of assessed rubric categories.
    pub categories_assessed: usize,
    /// Total rubric categories.
    pub categories_total: usize,
    /// Optional per-category breakdown.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub by_category: BTreeMap<String, f64>,
}

impl Statement {
    /// Parses `bytes` as JSON and validates every envelope, subject digest, and
    /// predicate invariant offline.
    pub fn parse(bytes: &[u8]) -> Result<Self, AttestationError> {
        let statement: Self = serde_json::from_slice(bytes)
            .map_err(|err| AttestationError::MalformedJson(err.to_string()))?;
        statement.validate()?;
        Ok(statement)
    }

    /// Validates all structural, target-descriptor digest, basis, and verdict-tally rules.
    pub fn validate(&self) -> Result<(), AttestationError> {
        let mut issues = Vec::new();
        if self.statement_type != STATEMENT_TYPE {
            issues.push(format!(
                "_type is {:?}, want {:?}",
                self.statement_type, STATEMENT_TYPE
            ));
        }
        if self.predicate_type != PREDICATE_TYPE {
            issues.push(format!(
                "predicateType is {:?}, want {:?}",
                self.predicate_type, PREDICATE_TYPE
            ));
        }
        self.validate_subject(&mut issues);
        self.validate_predicate_fields(&mut issues);
        self.validate_verdicts(&mut issues);
        if issues.is_empty() {
            Ok(())
        } else {
            Err(AttestationError::InvalidStatement(issues))
        }
    }

    /// Reports whether the single subject carries at least one known digest
    /// (`sha256` or `sha512`) and every known digest matches
    /// `format!("{}\n{}", transport, endpoint.trim())`.
    pub fn covers(&self, transport: &str, endpoint: &str) -> bool {
        if self.subject.len() != 1 {
            return false;
        }
        let desc = target_descriptor(transport, endpoint);
        let (found, mismatch) = check_digests(&self.subject[0].digest, &desc);
        found && mismatch.is_none()
    }

    /// Returns the first verdict recorded for `check_id`, or `AttestationError::NoSuchCheck`.
    pub fn verdict_for(&self, check_id: &str) -> Result<&Verdict, AttestationError> {
        self.predicate
            .verdicts
            .iter()
            .find(|v| v.id == check_id)
            .ok_or_else(|| AttestationError::NoSuchCheck(check_id.to_string()))
    }

    fn validate_subject(&self, issues: &mut Vec<String>) {
        match self.subject.as_slice() {
            [] => issues.push("no subject: the statement is about nothing".to_string()),
            [sub] => {
                let want = self.predicate.target.endpoint.trim();
                let got = sub.name.trim();
                if got.is_empty() {
                    issues.push("the subject has no name".to_string());
                } else if got != want {
                    issues.push(format!(
                        "the subject is named {:?} but the predicate is about {:?}",
                        sub.name, want
                    ));
                }
                let desc = target_descriptor(
                    &self.predicate.target.transport,
                    &self.predicate.target.endpoint,
                );
                match check_digests(&sub.digest, &desc) {
                    (false, _) => {
                        issues.push("the subject has no sha256 or sha512 digest".to_string());
                    }
                    (true, Some(alg)) => issues.push(format!(
                        "the subject {alg} digest does not cover the target it names"
                    )),
                    (true, None) => {}
                }
            }
            many => issues.push(format!(
                "{} subjects: a passmcp evaluation is about one server",
                many.len()
            )),
        }
    }

    fn validate_predicate_fields(&self, issues: &mut Vec<String>) {
        let p = &self.predicate;
        if p.subject_kind != SUBJECT_KIND_DESCRIPTOR {
            issues.push(format!(
                "subjectKind is {:?}, want {:?}",
                p.subject_kind, SUBJECT_KIND_DESCRIPTOR
            ));
        }
        if p.target.endpoint.trim().is_empty() {
            issues.push("the target has no endpoint".to_string());
        }
        match p.target.transport.as_str() {
            "http" | "stdio" => {}
            "" => issues.push("the target has no transport".to_string()),
            other => issues.push(format!("unknown transport {other:?}")),
        }
        if p.instrument.name.trim().is_empty() || p.instrument.version.trim().is_empty() {
            issues.push("the instrument is not identified".to_string());
        }
        if p.ran_at.trim().is_empty() || p.ran_at.trim() == "0001-01-01T00:00:00Z" {
            issues.push("no run time".to_string());
        }
        if p.verdicts.is_empty() {
            issues.push("no verdicts".to_string());
        }
        if p.judged_against.check_inventory.trim().is_empty() {
            issues.push("judgedAgainst.checkInventory is empty".to_string());
        }
        if p.score.is_some() && p.judged_against.rubric.trim().is_empty() {
            issues.push("a score with no rubric version".to_string());
        }
    }

    fn validate_verdicts(&self, issues: &mut Vec<String>) {
        let mut tallied = Counts::default();
        for (idx, verdict) in self.predicate.verdicts.iter().enumerate() {
            if verdict.id.trim().is_empty() {
                issues.push(format!("verdict {idx} has no id"));
                continue;
            }
            match verdict.status.as_str() {
                "pass" => tallied.pass += 1,
                "warn" => tallied.warn += 1,
                "fail" => tallied.fail += 1,
                "skip" => tallied.skip += 1,
                "info" => tallied.info += 1,
                other => issues.push(format!("verdict {} has status {other:?}", verdict.id)),
            }
        }
        if !self.predicate.verdicts.is_empty() && tallied != self.predicate.counts {
            issues.push(format!(
                "the counts disagree with the verdicts: says {:?}, tallied {:?}",
                self.predicate.counts, tallied
            ));
        }
    }
}

/// Computes the canonical UTF-8 target descriptor `format!("{}\n{}", transport, endpoint.trim())`.
pub fn target_descriptor(transport: &str, endpoint: &str) -> String {
    format!("{}\n{}", transport, endpoint.trim())
}

/// Parses `bytes`, verifies coverage of `(transport, endpoint)`, enforces
/// `min_score`, and rejects failing verdicts matching any check ID or phase in `deny_fail_in`.
pub fn verify_target(
    bytes: &[u8],
    transport: &str,
    endpoint: &str,
    min_score: Option<f64>,
    deny_fail_in: &[&str],
) -> Result<Statement, AttestationError> {
    let st = Statement::parse(bytes)?;
    if !st.covers(transport, endpoint) {
        return Err(AttestationError::TargetMismatch {
            transport: transport.to_string(),
            endpoint: endpoint.trim().to_string(),
        });
    }
    if let Some(floor) = min_score {
        let score =
            st.predicate.score.as_ref().ok_or_else(|| {
                AttestationError::PolicyRejected("statement carries no score".into())
            })?;
        if score.total < floor {
            return Err(AttestationError::PolicyRejected(format!(
                "score {:.2} is below minimum {:.2}",
                score.total, floor
            )));
        }
    }
    for selector in deny_fail_in {
        let sel = selector.trim();
        if sel.is_empty() {
            continue;
        }
        if let Some(v) = st.predicate.verdicts.iter().find(|v| {
            v.status == "fail"
                && (v.id == sel || v.phase == sel || v.id.starts_with(&format!("{sel}.")))
        }) {
            return Err(AttestationError::PolicyRejected(format!(
                "denied failure {} in phase {}",
                v.id, v.phase
            )));
        }
    }
    Ok(st)
}

fn check_digests<'a>(
    digests: &BTreeMap<String, String>,
    descriptor: &str,
) -> (bool, Option<&'a str>) {
    let mut found = false;
    let mut mismatch = None;
    if let Some(got) = digests.get("sha256") {
        found = true;
        if got != &sha256_hex(descriptor.as_bytes()) {
            mismatch = Some("sha256");
        }
    }
    if let Some(got) = digests.get("sha512") {
        found = true;
        if got != &sha512_hex(descriptor.as_bytes()) && mismatch.is_none() {
            mismatch = Some("sha512");
        }
    }
    (found, mismatch)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let sum = Sha256::digest(bytes);
    encode_lower_hex(&sum)
}

fn sha512_hex(bytes: &[u8]) -> String {
    let sum = Sha512::digest(bytes);
    encode_lower_hex(&sum)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}
