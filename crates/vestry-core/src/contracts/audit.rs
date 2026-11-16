//! C5 audit event schema, canonical encoder and golden vectors.
//!
//! The encoder is an explicit writer: no `serde_json::to_string`, no map
//! iteration order. Rules: LLD §9 lines 429–433; vectors are normative.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use super::adapter::Role;
use super::primitives::{
    AdmissionId, AnchorId, AttemptId, AuditSequence, CertificateId, CriterionId, DaemonGeneration,
    DispatchId, DispatchOrdinal, EvidenceId, Fence, GitSha, GoalId, Hash32, IdempotencyKey,
    LeaseId, PolicyRevision, Revision, SafeCode, SafeText, ScratchScope, Sha256Digest, TaskId,
    UtcMillis,
};

/// Domain separation string for audit v1 (C5 rule 11).
pub const AUDIT_DOMAIN_V1: &[u8] = b"vestry.audit.event.v1";
pub const AUDIT_SCHEMA_VERSION: u16 = 1;
pub const MAX_AUDIT_EVENT_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Event schema (C5 §6.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventDraft {
    /// Exactly 1 in S1.
    pub schema_version: u16,
    pub actor: AuditActor,
    pub action: AuditAction,
    pub scope: AuditScope,
    /// Sorted, unique.
    pub policy_refs: Vec<PolicyRef>,
    /// Sorted, unique.
    pub evidence_refs: Vec<EvidenceId>,
    pub outcome: AuditOutcome,
    pub recorded_at_ms: UtcMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditActor {
    Supervisor { generation: DaemonGeneration },
    Chief { generation: DaemonGeneration },
    Doctor { generation: DaemonGeneration },
    Owner { generation: DaemonGeneration },
}

impl AuditActor {
    pub fn generation(&self) -> DaemonGeneration {
        match self {
            Self::Supervisor { generation }
            | Self::Chief { generation }
            | Self::Doctor { generation }
            | Self::Owner { generation } => *generation,
        }
    }

    pub fn kind_code(&self) -> &'static str {
        match self {
            Self::Supervisor { .. } => "supervisor",
            Self::Chief { .. } => "chief",
            Self::Doctor { .. } => "doctor",
            Self::Owner { .. } => "owner",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditAction {
    Denial {
        operation: AuditOperation,
        reason: AuditReason,
    },
    StateTransition {
        from: StateCode,
        to: StateCode,
    },
    EffectIntent {
        operation: AuditOperation,
        intent_key: IdempotencyKey,
    },
    TerminationProof {
        dispatch_id: DispatchId,
        evidence_id: EvidenceId,
        proof_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditScope {
    PreAnchorDiscovery(PreAnchorDiscoveryScope),
    AnchoredInvocation(AnchoredInvocationScope),
    /// Non-dispatch daemon events (generation, migration, lock/Doctor).
    Daemon {
        generation: DaemonGeneration,
    },
    /// Non-dispatch object events (attention, evidence, policy).
    Object {
        object: super::status::ObjectRef,
    },
}

/// C5 scope projection of C3's pre-anchor discovery binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreAnchorDiscoveryScope {
    pub goal_id: GoalId,
    pub intake_digest: Sha256Digest,
    pub intake_revision: Revision,
    pub target_digest: Sha256Digest,
    pub scratch_scope: ScratchScope,
    /// Must be Discovery.
    pub role: Role,
    pub admission_id: AdmissionId,
    pub attempt_id: AttemptId,
    pub dispatch_ordinal: DispatchOrdinal,
    pub fence: Fence,
}

/// C5 scope projection of C3's anchored invocation binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchoredInvocationScope {
    pub goal_id: GoalId,
    pub anchor_id: AnchorId,
    /// Nonempty, sorted, unique.
    pub criterion_ids: Vec<CriterionId>,
    pub admission_id: AdmissionId,
    pub attempt_id: AttemptId,
    pub dispatch_ordinal: DispatchOrdinal,
    pub fence: Fence,
    pub role: Role,
    pub base_sha: GitSha,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_ref: Option<CertificateId>,
    pub gate_refs: Vec<AuditGateRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_revision: Option<Revision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<LeaseId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch_id: Option<DispatchId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditOutcome {
    Succeeded,
    Denied,
    Failed { reason: AuditReason },
    Recorded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateCode {
    Discovery,
    Architecture,
    Planning,
    Executing,
    Integrating,
    AwaitingAcceptance,
    Accepted,
    Planned,
    Ready,
    Running,
    Verifying,
    Reviewing,
    RepairPending,
    VerifiedHandoff,
    Blocked,
    RecoveryRequired,
    IntegratedClosed,
    Withdrawn,
    Cancelled,
    Reserved,
    LaunchIntent,
    Succeeded,
    Failed,
    CancelPending,
}

impl StateCode {
    pub fn code(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Architecture => "architecture",
            Self::Planning => "planning",
            Self::Executing => "executing",
            Self::Integrating => "integrating",
            Self::AwaitingAcceptance => "awaiting_acceptance",
            Self::Accepted => "accepted",
            Self::Planned => "planned",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Verifying => "verifying",
            Self::Reviewing => "reviewing",
            Self::RepairPending => "repair_pending",
            Self::VerifiedHandoff => "verified_handoff",
            Self::Blocked => "blocked",
            Self::RecoveryRequired => "recovery_required",
            Self::IntegratedClosed => "integrated_closed",
            Self::Withdrawn => "withdrawn",
            Self::Cancelled => "cancelled",
            Self::Reserved => "reserved",
            Self::LaunchIntent => "launch_intent",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::CancelPending => "cancel_pending",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditOperation(pub SafeCode);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditReason(pub SafeCode);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditGateRef(pub SafeCode);

/// A policy reference is a safe code `policy:<revision>` with optional
/// `:<clause>` and `:<grant>` segments. The golden vectors fix the string
/// form (`"policy:7"`); fields remain typed for Phase C policy data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PolicyRef {
    pub revision: PolicyRevision,
    pub clause: Option<SafeCode>,
    pub grant: Option<SafeCode>,
}

impl PolicyRef {
    pub fn revision(revision: PolicyRevision) -> Self {
        Self {
            revision,
            clause: None,
            grant: None,
        }
    }

    pub fn with_clause(mut self, clause: SafeCode) -> Self {
        self.clause = Some(clause);
        self
    }

    pub fn with_grant(mut self, grant: SafeCode) -> Self {
        self.grant = Some(grant);
        self
    }

    pub fn as_string(&self) -> String {
        let mut text = format!("policy:{}", self.revision.get());
        if let Some(clause) = &self.clause {
            text.push(':');
            text.push_str(clause.as_str());
        }
        if let Some(grant) = &self.grant {
            text.push(':');
            text.push_str(grant.as_str());
        }
        text
    }
}

impl From<PolicyRef> for String {
    fn from(reference: PolicyRef) -> Self {
        reference.as_string()
    }
}

impl TryFrom<String> for PolicyRef {
    type Error = CanonicalError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let rest = text
            .strip_prefix("policy:")
            .ok_or(CanonicalError::InvalidPolicyRef)?;
        let mut parts = rest.split(':');
        let revision = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(CanonicalError::InvalidPolicyRef)?;
        let clause = parts
            .next()
            .map(SafeCode::new)
            .transpose()
            .map_err(|_| CanonicalError::InvalidPolicyRef)?;
        let grant = parts
            .next()
            .map(SafeCode::new)
            .transpose()
            .map_err(|_| CanonicalError::InvalidPolicyRef)?;
        if parts.next().is_some() {
            return Err(CanonicalError::InvalidPolicyRef);
        }
        Ok(Self {
            revision: PolicyRevision(revision),
            clause,
            grant,
        })
    }
}

impl Ord for PolicyRef {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_string().cmp(&other.as_string())
    }
}

impl PartialOrd for PolicyRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The committed event adds the chain fields; `event_hash` is never accepted
/// from a draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub sequence: AuditSequence,
    pub previous_hash: Hash32,
    pub schema_version: u16,
    pub actor: AuditActor,
    pub action: AuditAction,
    pub scope: AuditScope,
    pub policy_refs: Vec<PolicyRef>,
    pub evidence_refs: Vec<EvidenceId>,
    pub outcome: AuditOutcome,
    pub recorded_at_ms: UtcMillis,
    pub event_hash: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditHead {
    pub sequence: AuditSequence,
    pub hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerdict {
    Empty,
    Valid {
        head: AuditHead,
    },
    Broken {
        at_sequence: AuditSequence,
        expected_previous: Hash32,
        found_previous: Hash32,
    },
    HeadMismatch {
        computed: AuditHead,
        trusted: AuditHead,
    },
    EventHashMismatch {
        at_sequence: AuditSequence,
        expected: Hash32,
        found: Hash32,
    },
}

// ---------------------------------------------------------------------------
// Canonical writer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    #[error("float is not allowed in canonical audit JSON")]
    FloatNotAllowed,
    #[error("null is not allowed in canonical audit JSON")]
    NullNotAllowed,
    #[error("control character is not allowed in an audit string")]
    ControlCharacter,
    #[error("duplicate object key")]
    DuplicateKey,
    #[error("unsupported number")]
    UnsupportedNumber,
    #[error("unknown field {0}")]
    UnknownField(String),
    #[error("missing field {0}")]
    MissingField(String),
    #[error("event_hash must not be supplied by a draft")]
    HashFieldPresent,
    #[error("field {0} is not in canonical order")]
    UnsortedArray(&'static str),
    #[error("array elements must be unique")]
    DuplicateElement(&'static str),
    #[error("invalid JSON input")]
    InvalidJson,
    #[error("invalid hex hash")]
    InvalidHex,
    #[error("invalid policy reference")]
    InvalidPolicyRef,
    #[error("schema version is not supported")]
    SchemaMismatch,
    #[error("canonical bytes exceed {limit} bytes")]
    Oversize { limit: usize },
}

/// Intermediate canonical value; the only writer is [`write_canon`].
#[derive(Debug, Clone)]
pub enum Canon<'a> {
    Str(&'a str),
    OwnedStr(String),
    UInt(u128),
    Int(i128),
    Bool(bool),
    Arr(Vec<Canon<'a>>),
    Obj(Vec<(&'a str, Canon<'a>)>),
    OwnedObj(Vec<(String, Canon<'a>)>),
}

fn write_string(out: &mut String, value: &str) -> Result<(), CanonicalError> {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0000}'..='\u{001F}' | '\u{007F}' => return Err(CanonicalError::ControlCharacter),
            other => out.push(other),
        }
    }
    out.push('"');
    Ok(())
}

fn write_canon(out: &mut String, value: &Canon<'_>) -> Result<(), CanonicalError> {
    match value {
        Canon::Str(text) => write_string(out, text),
        Canon::OwnedStr(text) => write_string(out, text),
        Canon::UInt(number) => {
            out.push_str(&number.to_string());
            Ok(())
        }
        Canon::Int(number) => {
            out.push_str(&number.to_string());
            Ok(())
        }
        Canon::Bool(flag) => {
            out.push_str(if *flag { "true" } else { "false" });
            Ok(())
        }
        Canon::Arr(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canon(out, item)?;
            }
            out.push(']');
            Ok(())
        }
        Canon::OwnedObj(members) => {
            let mut sorted: Vec<&(String, Canon<'_>)> = members.iter().collect();
            sorted.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            for window in sorted.windows(2) {
                if window[0].0 == window[1].0 {
                    return Err(CanonicalError::DuplicateKey);
                }
            }
            out.push('{');
            for (index, (key, item)) in sorted.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key)?;
                out.push(':');
                write_canon(out, item)?;
            }
            out.push('}');
            Ok(())
        }
        Canon::Obj(members) => {
            let mut sorted: Vec<&(&str, Canon<'_>)> = members.iter().collect();
            sorted.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            for window in sorted.windows(2) {
                if window[0].0 == window[1].0 {
                    return Err(CanonicalError::DuplicateKey);
                }
            }
            out.push('{');
            for (index, (key, item)) in sorted.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key)?;
                out.push(':');
                write_canon(out, item)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

/// Explicit canonical encoder. Never calls `serde_json::to_string`.
pub fn encode_canon(value: &Canon<'_>) -> Result<Vec<u8>, CanonicalError> {
    let mut out = String::new();
    write_canon(&mut out, value)?;
    if out.len() > MAX_AUDIT_EVENT_BYTES {
        return Err(CanonicalError::Oversize {
            limit: MAX_AUDIT_EVENT_BYTES,
        });
    }
    Ok(out.into_bytes())
}

/// Domain-separated digest: `SHA-256("vestry.audit.event.v1" || 0x00 || bytes)`.
pub fn domain_digest(domain: &[u8], bytes: &[u8]) -> Hash32 {
    let mut buffer = Vec::with_capacity(domain.len() + 1 + bytes.len());
    buffer.extend_from_slice(domain);
    buffer.push(0);
    buffer.extend_from_slice(bytes);
    Hash32(Sha256Digest::digest(&buffer).bytes.0)
}

fn object_code(object: &super::status::ObjectRef) -> String {
    use super::status::ObjectRef as O;
    let (kind, value): (&str, String) = match object {
        O::Goal(id) => ("goal", id.as_str().to_owned()),
        O::Task(id) => ("task", id.as_str().to_owned()),
        O::Attempt(id) => ("attempt", id.as_str().to_owned()),
        O::Dispatch(id) => ("dispatch", id.as_str().to_owned()),
        O::Lease(id) => ("lease", id.as_str().to_owned()),
        O::Process(id) => ("process", id.as_str().to_owned()),
        O::Evidence(id) => ("evidence", id.as_str().to_owned()),
        O::Daemon(generation) => ("daemon", generation.get().to_string()),
    };
    format!("{kind}:{value}")
}

fn role_code(role: Role) -> &'static str {
    match role {
        Role::Discovery => "discovery",
        Role::Architect => "architect",
        Role::Planner => "planner",
        Role::Worker => "worker",
        Role::Reviewer => "reviewer",
        Role::VerifierJudgement => "verifier_judgement",
    }
}

fn action_canon<'a>(action: &'a AuditAction) -> Result<Canon<'a>, CanonicalError> {
    Ok(match action {
        AuditAction::Denial { operation, reason } => Canon::Obj(vec![
            ("kind", Canon::Str("denial")),
            ("operation", Canon::Str(operation.0.as_str())),
            ("reason", Canon::Str(reason.0.as_str())),
        ]),
        AuditAction::StateTransition { from, to } => Canon::Obj(vec![
            ("from", Canon::Str(from.code())),
            ("kind", Canon::Str("state_transition")),
            ("to", Canon::Str(to.code())),
        ]),
        AuditAction::EffectIntent {
            operation,
            intent_key,
        } => Canon::Obj(vec![
            ("intent_key", Canon::Str(intent_key.as_str())),
            ("kind", Canon::Str("effect_intent")),
            ("operation", Canon::Str(operation.0.as_str())),
        ]),
        AuditAction::TerminationProof {
            dispatch_id,
            evidence_id,
            proof_digest,
        } => Canon::Obj(vec![
            ("dispatch_id", Canon::Str(dispatch_id.as_str())),
            ("evidence_id", Canon::Str(evidence_id.as_str())),
            ("kind", Canon::Str("termination_proof")),
            ("proof_digest", Canon::OwnedStr(proof_digest.to_string())),
        ]),
    })
}

fn outcome_canon(outcome: &AuditOutcome) -> Canon<'_> {
    match outcome {
        AuditOutcome::Succeeded => Canon::Obj(vec![("kind", Canon::Str("succeeded"))]),
        AuditOutcome::Denied => Canon::Obj(vec![("kind", Canon::Str("denied"))]),
        AuditOutcome::Failed { reason } => Canon::Obj(vec![
            ("kind", Canon::Str("failed")),
            ("reason", Canon::Str(reason.0.as_str())),
        ]),
        AuditOutcome::Recorded => Canon::Obj(vec![("kind", Canon::Str("recorded"))]),
    }
}

/// Canonical bytes of a committed event, excluding `event_hash`.
pub fn canonical_bytes(event: &AuditEvent) -> Result<Vec<u8>, CanonicalError> {
    if event.schema_version != AUDIT_SCHEMA_VERSION {
        return Err(CanonicalError::SchemaMismatch);
    }
    if !event.policy_refs.windows(2).all(|w| w[0] < w[1]) {
        return Err(CanonicalError::UnsortedArray("policy_refs"));
    }
    if !event.evidence_refs.windows(2).all(|w| w[0] < w[1]) {
        return Err(CanonicalError::UnsortedArray("evidence_refs"));
    }
    let previous_hex = event.previous_hash.to_hex();
    let policy_strings: Vec<String> = event.policy_refs.iter().map(PolicyRef::as_string).collect();
    let gate_refs: Vec<String> = match &event.scope {
        AuditScope::AnchoredInvocation(anchored) => anchored
            .gate_refs
            .iter()
            .map(|reference| reference.0.as_str().to_owned())
            .collect(),
        _ => Vec::new(),
    };

    let role = match &event.scope {
        AuditScope::PreAnchorDiscovery(discovery) => role_code(discovery.role),
        AuditScope::AnchoredInvocation(anchored) => role_code(anchored.role),
        AuditScope::Daemon { .. } | AuditScope::Object { .. } => "",
    };

    let scope = match &event.scope {
        // Rebuild inline so digest strings borrow from `event` (no leak).
        AuditScope::PreAnchorDiscovery(discovery) => {
            let intake = discovery.intake_digest.to_string();
            let target = discovery.target_digest.to_string();
            Canon::Obj(vec![
                ("admission_id", Canon::Str(discovery.admission_id.as_str())),
                ("attempt_id", Canon::Str(discovery.attempt_id.as_str())),
                (
                    "dispatch_ordinal",
                    Canon::UInt(discovery.dispatch_ordinal.get() as u128),
                ),
                ("fence", Canon::UInt(discovery.fence.get() as u128)),
                ("goal_id", Canon::Str(discovery.goal_id.as_str())),
                ("intake_digest", Canon::OwnedStr(intake)),
                (
                    "intake_revision",
                    Canon::UInt(discovery.intake_revision.get() as u128),
                ),
                ("kind", Canon::Str("pre_anchor_discovery")),
                ("role", Canon::Str(role)),
                (
                    "scratch_scope",
                    Canon::Str(discovery.scratch_scope.as_str()),
                ),
                ("target_digest", Canon::OwnedStr(target)),
            ])
        }
        AuditScope::AnchoredInvocation(anchored) => {
            let base = anchored.base_sha.to_string();
            let mut members: Vec<(&str, Canon<'_>)> = vec![
                ("admission_id", Canon::Str(anchored.admission_id.as_str())),
                ("anchor_id", Canon::Str(anchored.anchor_id.as_str())),
                ("attempt_id", Canon::Str(anchored.attempt_id.as_str())),
                ("base_sha", Canon::OwnedStr(base)),
                (
                    "criterion_ids",
                    Canon::Arr(
                        anchored
                            .criterion_ids
                            .iter()
                            .map(|id| Canon::Str(id.as_str()))
                            .collect(),
                    ),
                ),
                (
                    "dispatch_ordinal",
                    Canon::UInt(anchored.dispatch_ordinal.get() as u128),
                ),
                ("fence", Canon::UInt(anchored.fence.get() as u128)),
                (
                    "gate_refs",
                    Canon::Arr(gate_refs.iter().map(|r| Canon::Str(r)).collect()),
                ),
                ("goal_id", Canon::Str(anchored.goal_id.as_str())),
                ("kind", Canon::Str("anchored_invocation")),
                ("role", Canon::Str(role)),
            ];
            if let Some(certificate) = &anchored.certificate_ref {
                members.push(("certificate_ref", Canon::Str(certificate.as_str())));
            }
            if let Some(dispatch) = &anchored.dispatch_id {
                members.push(("dispatch_id", Canon::Str(dispatch.as_str())));
            }
            if let Some(lease) = &anchored.lease_id {
                members.push(("lease_id", Canon::Str(lease.as_str())));
            }
            if let Some(task) = &anchored.task_id {
                members.push(("task_id", Canon::Str(task.as_str())));
            }
            if let Some(revision) = anchored.task_revision {
                members.push(("task_revision", Canon::UInt(revision.get() as u128)));
            }
            Canon::Obj(members)
        }
        AuditScope::Daemon { generation } => Canon::Obj(vec![
            ("generation", Canon::UInt(generation.get() as u128)),
            ("kind", Canon::Str("daemon")),
        ]),
        AuditScope::Object { object } => {
            let code = object_code(object);
            Canon::Obj(vec![
                ("kind", Canon::Str("object")),
                ("object", Canon::OwnedStr(code)),
            ])
        }
    };

    let actor = Canon::Obj(vec![
        (
            "generation",
            Canon::UInt(event.actor.generation().get() as u128),
        ),
        ("kind", Canon::Str(event.actor.kind_code())),
    ]);

    let action = action_canon(&event.action)?;

    let event_body = Canon::Obj(vec![
        ("action", action),
        ("actor", actor),
        (
            "evidence_refs",
            Canon::Arr(
                event
                    .evidence_refs
                    .iter()
                    .map(|id| Canon::Str(id.as_str()))
                    .collect(),
            ),
        ),
        ("outcome", outcome_canon(&event.outcome)),
        (
            "policy_refs",
            Canon::Arr(policy_strings.iter().map(|r| Canon::Str(r)).collect()),
        ),
        ("previous_hash", Canon::Str(&previous_hex)),
        ("recorded_at_ms", Canon::Int(event.recorded_at_ms.0 as i128)),
        ("schema_version", Canon::UInt(event.schema_version as u128)),
        ("sequence", Canon::UInt(event.sequence.get() as u128)),
        ("scope", scope),
    ]);

    encode_canon(&event_body)
}

/// `event_hash` for an event whose `previous_hash` and body are fixed.
pub fn compute_event_hash(event: &AuditEvent) -> Result<Hash32, CanonicalError> {
    let bytes = canonical_bytes(event)?;
    Ok(domain_digest(AUDIT_DOMAIN_V1, &bytes))
}

impl AuditEvent {
    pub fn verify_event_hash(&self) -> ChainVerdict {
        match compute_event_hash(self) {
            Ok(expected) if expected == self.event_hash => ChainVerdict::Valid {
                head: AuditHead {
                    sequence: self.sequence,
                    hash: self.event_hash,
                },
            },
            Ok(expected) => ChainVerdict::EventHashMismatch {
                at_sequence: self.sequence,
                expected,
                found: self.event_hash,
            },
            Err(_) => ChainVerdict::EventHashMismatch {
                at_sequence: self.sequence,
                expected: self.event_hash,
                found: self.event_hash,
            },
        }
    }
}

/// Verifies contiguity from sequence 1, the genesis previous hash, each link,
/// every event hash, and the trusted head when supplied.
pub fn verify_chain(events: &[AuditEvent], trusted_head: Option<AuditHead>) -> ChainVerdict {
    let Some(first) = events.first() else {
        return ChainVerdict::Empty;
    };
    if first.sequence.get() != 1 || !first.previous_hash.is_zero() {
        return ChainVerdict::Broken {
            at_sequence: first.sequence,
            expected_previous: Hash32::ZERO,
            found_previous: first.previous_hash,
        };
    }
    let mut previous: Option<&AuditEvent> = None;
    for event in events {
        let expected_sequence = previous
            .map(|p| p.sequence.next())
            .unwrap_or(AuditSequence(1));
        if event.sequence != expected_sequence {
            return ChainVerdict::Broken {
                at_sequence: event.sequence,
                expected_previous: previous.map(|p| p.event_hash).unwrap_or(Hash32::ZERO),
                found_previous: event.previous_hash,
            };
        }
        if let Some(prior) = previous {
            if event.previous_hash != prior.event_hash {
                return ChainVerdict::Broken {
                    at_sequence: event.sequence,
                    expected_previous: prior.event_hash,
                    found_previous: event.previous_hash,
                };
            }
        }
        if let ChainVerdict::EventHashMismatch { .. } = event.verify_event_hash() {
            return event.verify_event_hash();
        }
        previous = Some(event);
    }
    let last = events.last().expect("non-empty");
    let head = AuditHead {
        sequence: last.sequence,
        hash: last.event_hash,
    };
    match trusted_head {
        Some(trusted) if trusted != head => ChainVerdict::HeadMismatch {
            computed: head,
            trusted,
        },
        _ => ChainVerdict::Valid { head },
    }
}

/// Decodes raw JSON into canonical bytes, enforcing every C5 rule. Used to
/// prove rejection of floats, nulls, control characters and an `event_hash`
/// member; the typed encoder is the audit path.
pub fn canonicalize_json_bytes(input: &[u8]) -> Result<Vec<u8>, CanonicalError> {
    let value: serde_json::Value =
        serde_json::from_slice(input).map_err(|_| CanonicalError::InvalidJson)?;
    if let serde_json::Value::Object(map) = &value {
        if map.contains_key("event_hash") {
            return Err(CanonicalError::HashFieldPresent);
        }
        for required in [
            "sequence",
            "previous_hash",
            "schema_version",
            "actor",
            "action",
            "scope",
            "policy_refs",
            "evidence_refs",
            "outcome",
            "recorded_at_ms",
        ] {
            if !map.contains_key(required) {
                return Err(CanonicalError::MissingField(required.to_owned()));
            }
        }
        for key in map.keys() {
            if ![
                "sequence",
                "previous_hash",
                "schema_version",
                "actor",
                "action",
                "scope",
                "policy_refs",
                "evidence_refs",
                "outcome",
                "recorded_at_ms",
            ]
            .contains(&key.as_str())
            {
                return Err(CanonicalError::UnknownField(key.clone()));
            }
        }
    }
    let owned = value_to_canon(value)?;
    encode_canon(&owned)
}

fn value_to_canon(value: serde_json::Value) -> Result<Canon<'static>, CanonicalError> {
    use serde_json::Value;
    Ok(match value {
        Value::Null => return Err(CanonicalError::NullNotAllowed),
        Value::Bool(flag) => Canon::Bool(flag),
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                Canon::UInt(unsigned as u128)
            } else if let Some(signed) = number.as_i64() {
                Canon::Int(signed as i128)
            } else {
                return Err(CanonicalError::FloatNotAllowed);
            }
        }
        Value::String(text) => Canon::OwnedStr(text),
        Value::Array(items) => Canon::Arr(
            items
                .into_iter()
                .map(value_to_canon)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Object(map) => Canon::OwnedObj(
            map.into_iter()
                .map(|(key, item)| Ok((key, value_to_canon(item)?)))
                .collect::<Result<Vec<_>, CanonicalError>>()?,
        ),
    })
}

/// Text safety used by scope values: rejects control characters (C5 rule 5).
pub fn validate_safe_text(text: &str) -> Result<(), CanonicalError> {
    match SafeText::new(text) {
        Ok(_) => Ok(()),
        Err(_) => Err(CanonicalError::ControlCharacter),
    }
}
