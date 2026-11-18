//! C3 adapter contracts: capability state, canary, environment, usage, NDJSON
//! and the four identities. Design: LLD §1 lines 13–70, §8.1–§8.7.
//!
//! Contract types only; no adapter, parser or process mechanics live here.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::pin::{
    AdapterId, ApiAliasOrTag, CredentialRef, EnvironmentName, InstallationVersion, LogicalModelId,
    ModelDetails, ModelPin, ProviderId, ProviderSlug, RuntimeVersion,
};
use super::primitives::{
    AttemptId, CanaryId, ConditionId, EvidenceId, ManifestId, MessageId, PartId, RedactionVersion,
    SafeCode, SafeText, SessionId, Sha256Digest, SnapshotRef, UtcMillis,
};

// ---------------------------------------------------------------------------
// Capability state and manifest (C3 §4.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Supported,
    Unsupported,
    Conditional,
    Unverified,
}

impl CapabilityState {
    /// `Conditional` is available only when every condition is independently
    /// current; `Unverified` is never available (LLD §1 line 30).
    pub fn is_available(self, all_conditions_current: bool) -> bool {
        match self {
            Self::Supported => true,
            Self::Conditional => all_conditions_current,
            Self::Unsupported | Self::Unverified => false,
        }
    }

    /// Flattened spelling is the enum's wire value.
    pub fn as_code(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unsupported => "unsupported",
            Self::Conditional => "conditional",
            Self::Unverified => "unverified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityId {
    FinalToolPolicy,
    StepUsage,
    ResolvedModelIdentity,
    ServedModelIdentity,
    SessionResume,
    SanitizedExport,
    CooperativeAbort,
    OwnedDescendantTermination,
    HardCrashCleanup,
    ExactEffectGrants,
    Revocation,
    SecretSafeCapture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEntry {
    pub id: CapabilityId,
    pub state: CapabilityState,
    /// Condition identifiers are data, each independently current before a
    /// `Conditional` entry is usable.
    pub conditions: Vec<ConditionId>,
    pub proof_ids: Vec<EvidenceId>,
    pub limitations: Vec<SafeText>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    pub manifest_id: ManifestId,
    pub schema_version: u16,
    pub adapter_id: AdapterId,
    pub installation_version: InstallationVersion,
    pub executable_digest: Sha256Digest,
    pub environment_fingerprint: super::primitives::EnvironmentFingerprint,
    pub policy_profile_digest: Sha256Digest,
    pub requested_model_pin: ModelPin,
    pub qualified_at: UtcMillis,
    pub platform: Platform,
    pub evidence_revision: super::primitives::EvidenceRevision,
    pub capabilities: Vec<CapabilityEntry>,
    pub validity: ManifestValidity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub os: OperatingSystem,
    pub arch: Architecture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestValidity {
    Current,
    Invalidated {
        reason: ManifestInvalidation,
        at: UtcMillis,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestInvalidation {
    FingerprintChanged,
    EvidenceInvalid,
    Superseded,
    OwnerRevoked,
    Expired,
}

impl CapabilityManifest {
    /// A `Conditional` entry needs at least one condition; a claimed
    /// `Unverified` capability is never available and is not a qualification.
    pub fn validate(&self) -> Result<(), AdapterError> {
        for entry in &self.capabilities {
            if entry.state == CapabilityState::Conditional && entry.conditions.is_empty() {
                return Err(AdapterError::ConditionalWithoutCondition);
            }
        }
        self.requested_model_pin
            .validate()
            .map_err(AdapterError::PinInvalid)?;
        Ok(())
    }

    pub fn is_current(&self) -> bool {
        matches!(self.validity, ManifestValidity::Current)
    }

    /// Admission requires a current manifest and a supported capability.
    pub fn require(&self, id: CapabilityId, conditions_current: bool) -> Result<(), AdapterError> {
        if !self.is_current() {
            return Err(AdapterError::ManifestNotCurrent(self.manifest_id.clone()));
        }
        let entry = self
            .capabilities
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(AdapterError::CapabilityUnavailable(id))?;
        if entry.state.is_available(conditions_current) {
            Ok(())
        } else {
            Err(AdapterError::CapabilityUnavailable(id))
        }
    }
}

// ---------------------------------------------------------------------------
// Canary (C3 §4.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Discovery,
    Architect,
    Planner,
    Worker,
    Reviewer,
    VerifierJudgement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchPath {
    CliDefault,
    PrivateServe,
}

/// Machine-observed tool name from the final inventory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ToolName(pub SafeCode);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRecord {
    pub canary_id: CanaryId,
    pub manifest_id: ManifestId,
    pub dispatch_path: DispatchPath,
    pub role: Role,
    pub policy_digest: Sha256Digest,
    pub model_pin: ModelPin,
    pub route_fingerprint: super::primitives::RouteFingerprint,
    pub result: super::status::EvidenceStatus,
    pub evidence: CanaryEvidence,
    pub evidence_digest: Sha256Digest,
    pub observed_at: UtcMillis,
    pub validity: CanaryValidity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanaryEvidence {
    /// Machine-observed final tool inventory for the actual session.
    FinalToolInventory {
        session_id: SessionId,
        inventory_digest: Sha256Digest,
        tool_names: Vec<ToolName>,
    },
    /// Machine-observed complete list proving the denied tool is absent.
    UnavailableToolProof {
        session_id: SessionId,
        absent_tool: ToolName,
        complete_tool_list: Vec<ToolName>,
    },
    /// Anything less is not PASS evidence.
    Insufficient { reason: CanaryEvidenceGap },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryEvidenceGap {
    ModelProseOnly,
    NoToolUseObserved,
    DebugInventoryOnly,
    SessionNotObserved,
    FingerprintMismatch,
    ParserUnsupported,
    CustomToolPathUnverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryValidity {
    Current,
    Invalidated {
        reason: CanaryInvalidation,
        at: UtcMillis,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryInvalidation {
    PinChanged,
    ManifestChanged,
    PolicyChanged,
    ConfigChanged,
    PluginChanged,
    Expired,
    EvidenceInvalid,
}

impl CanaryRecord {
    /// LLD §1 lines 54–55: PASS is only machine evidence; NOT RUN needs a
    /// reason; private-serve stays unqualified until separately qualified.
    pub fn validate(&self) -> Result<(), CanaryError> {
        self.result
            .validate()
            .map_err(|_| CanaryError::NotRunWithoutReason)?;
        if self.dispatch_path == DispatchPath::PrivateServe {
            return Err(CanaryError::PrivateServeUnqualified);
        }
        let names = match (&self.result.state, &self.evidence) {
            (
                super::status::EvidenceState::Pass,
                CanaryEvidence::FinalToolInventory { tool_names, .. },
            ) => tool_names,
            (
                super::status::EvidenceState::Pass,
                CanaryEvidence::UnavailableToolProof {
                    complete_tool_list, ..
                },
            ) => complete_tool_list,
            (super::status::EvidenceState::Pass, CanaryEvidence::Insufficient { .. }) => {
                return Err(CanaryError::PassWithoutMachineEvidence);
            }
            (super::status::EvidenceState::NotRun, CanaryEvidence::Insufficient { .. }) => {
                return Ok(());
            }
            (super::status::EvidenceState::NotRun, _) => {
                return Err(CanaryError::NotRunWithoutReason);
            }
            (super::status::EvidenceState::Fail, _) => return Ok(()),
        };
        if names.is_empty() || !names.windows(2).all(|window| window[0] < window[1]) {
            return Err(CanaryError::PassWithoutMachineEvidence);
        }
        Ok(())
    }

    pub fn is_current_pass(&self) -> bool {
        self.result.state == super::status::EvidenceState::Pass
            && matches!(self.validity, CanaryValidity::Current)
            && self.validate().is_ok()
    }
}

// ---------------------------------------------------------------------------
// Per-dispatch environment and permission policy (C3 §4.5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentAllowlist {
    pub entries: BTreeMap<EnvironmentName, EnvironmentValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnvironmentValue {
    Literal(String),
    SecretRef(CredentialRef),
}

impl EnvironmentAllowlist {
    /// The allowlist is the complete environment; this is the default for tests.
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<(), EnvironmentError> {
        for value in self.entries.values() {
            if let EnvironmentValue::Literal(literal) = value {
                if literal.contains('\0') || literal.contains('\r') || literal.contains('\n') {
                    return Err(EnvironmentError::InvalidLiteral);
                }
            }
        }
        Ok(())
    }

    /// Hashes sorted names plus `literal:`/`secret-ref:` markers; a secret
    /// reference is included, never the referenced value.
    pub fn fingerprint(
        &self,
    ) -> Result<super::primitives::EnvironmentFingerprint, EnvironmentError> {
        self.validate()?;
        let mut buffer = Vec::new();
        for (name, value) in &self.entries {
            buffer.extend_from_slice(name.0.as_bytes());
            buffer.push(b'=');
            match value {
                EnvironmentValue::Literal(literal) => {
                    buffer.extend_from_slice(b"literal:");
                    buffer.extend_from_slice(literal.as_bytes());
                }
                EnvironmentValue::SecretRef(reference) => {
                    buffer.extend_from_slice(b"secret-ref:");
                    buffer.extend_from_slice(reference.0.as_str().as_bytes());
                }
            }
            buffer.push(0);
        }
        Ok(super::primitives::EnvironmentFingerprint(
            Sha256Digest::digest(&buffer),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionPolicy {
    /// Ordered rules; the wildcard `*` must be first.
    pub rules: Vec<PermissionRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionRule {
    pub pattern: SafeText,
    pub action: PermissionAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    Allow,
    Ask,
    Deny,
}

impl PermissionPolicy {
    /// Order is the policy; wildcard-first is the only structural rule here.
    pub fn validate(&self) -> Result<(), EnvironmentError> {
        if self.rules.is_empty() {
            return Err(EnvironmentError::MalformedPermissionPolicy);
        }
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.pattern.as_str() == "*" && index != 0 {
                return Err(EnvironmentError::MalformedPermissionPolicy);
            }
        }
        Ok(())
    }

    /// Parses the literal `OPENCODE_PERMISSION` JSON before spawn. Malformed
    /// JSON is rejected; no heuristic repair.
    pub fn from_json(bytes: &[u8]) -> Result<Self, EnvironmentError> {
        let policy: Self = serde_json::from_slice(bytes)
            .map_err(|_| EnvironmentError::MalformedPermissionPolicy)?;
        policy.validate()?;
        Ok(policy)
    }
}

// ---------------------------------------------------------------------------
// Usage, normalized events (C3 §4.6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageStepKey {
    pub attempt_id: AttemptId,
    pub session_id: SessionId,
    pub part_id: PartId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenCounters {
    pub input: u64,
    pub output: u64,
    pub cache_read: Option<u64>,
    pub cache_write: Option<u64>,
    pub reasoning: Option<u64>,
    pub total: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageStep {
    pub key: UsageStepKey,
    pub counters: TokenCounters,
    /// `None` = unknown, `Some(0.0)` = reported zero (D44); zero is never
    /// treated as unknown.
    pub cost: Option<f64>,
    pub model_evidence: super::primitives::ModelEvidenceRef,
    pub duration_ms: Option<u64>,
    pub source: UsageSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    StepFinishStdout,
    ServerMessage,
    Snapshot,
}

impl UsageStep {
    pub fn validate(&self) -> Result<(), NdjsonError> {
        if let Some(cost) = self.cost {
            if !cost.is_finite() || cost < 0.0 {
                return Err(NdjsonError::InvalidNumber);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NormalizedEvent {
    OuterStepFinish(StepFinishEvent),
    InnerStepFinish(StepFinishEvent),
    PermissionRejection(RedactedDiagnostic),
    Malformed {
        class: MalformedClass,
    },
    Unknown {
        line_digest: Sha256Digest,
        length: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepFinishEvent {
    pub session_id: SessionId,
    pub part_id: PartId,
    pub message_id: Option<MessageId>,
    pub usage: UsageStep,
    pub snapshot: Option<SnapshotRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MalformedClass {
    Ansi,
    Multiline,
    InvalidUtf8,
    InvalidJson,
    Oversize,
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedDiagnostic {
    pub digest: Sha256Digest,
    pub length: u64,
    pub redaction_version: RedactionVersion,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionObservation {
    pub events: Vec<NormalizedEvent>,
    pub stream_complete: bool,
    pub exit_code: Option<u32>,
    pub stderr_digest: Option<Sha256Digest>,
}

impl SessionObservation {
    /// `exit_code == 0` alone is not success (LLD §1 line 70).
    pub fn is_acceptable_success(&self) -> bool {
        self.stream_complete
            && self.exit_code == Some(0)
            && self
                .events
                .iter()
                .all(|event| !matches!(event, NormalizedEvent::Malformed { .. }))
    }
}

// ---------------------------------------------------------------------------
// Four identities (C3 §4.6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRecord {
    pub requested: ModelPin,
    pub resolved: Option<ResolvedSelection>,
    pub outbound: Option<OutboundAlias>,
    pub served: Option<ServedIdentity>,
    pub provenance: Vec<IdentityProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSelection {
    pub provider: ProviderId,
    pub logical_model: LogicalModelId,
    pub source: IdentitySource,
    pub observed_at: UtcMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundAlias {
    pub alias: ApiAliasOrTag,
    pub source: IdentitySource,
    pub observed_at: UtcMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "channel", rename_all = "snake_case")]
pub enum ServedIdentity {
    OllamaTags {
        digest: Sha256Digest,
        size: u64,
        details: ModelDetails,
        runtime_version: RuntimeVersion,
        endpoint: super::pin::Endpoint,
        observed_at: UtcMillis,
    },
    GeminiModelVersion {
        model_version: SafeText,
        response_id: SafeText,
        model_stage: ModelStage,
        retirement_time_ms: Option<i64>,
        observed_at: UtcMillis,
    },
    OpenRouterGeneration {
        generation_id: SafeText,
        model: SafeText,
        provider_name: ProviderSlug,
        provider_responses: Vec<ProviderResponse>,
        observed_at: UtcMillis,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelStage {
    Stable,
    Preview,
    Legacy,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResponse {
    pub model: SafeText,
    pub provider_name: ProviderSlug,
    pub model_permaslug: SafeText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    ExportMessage,
    ServerMessage,
    ProviderReadback,
    LocalRuntimeQuery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProvenance {
    pub source: IdentitySource,
    pub observed_at: UtcMillis,
    pub evidence_digest: Sha256Digest,
}

impl IdentityRecord {
    /// `requested` is mandatory; a pin that needs served identity without one
    /// is `ServedIdentityMissing`, never a match.
    pub fn validate(&self) -> Result<(), PinFailure> {
        match &self.served {
            Some(ServedIdentity::OpenRouterGeneration {
                provider_responses, ..
            }) if provider_responses.len() > 1 => Err(PinFailure::ProviderFallback),
            Some(_) => Ok(()),
            None => Err(PinFailure::ServedIdentityMissing),
        }
    }

    /// The four identities are never collapsed.
    pub fn fields_are_separate(&self) -> bool {
        self.resolved.is_some()
            && self.outbound.is_some()
            && self.served.is_some()
            && !self.provenance.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Failure taxonomy (C3 §4.7 + C6 §7.5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinFailure {
    QuotaBeforeInference,
    QuotaAfterInference,
    ModelRetired,
    ProviderFallback,
    ServedIdentityMissing,
    ServedIdentityMismatch,
    MidSessionDivergence,
    LocalDigestMismatch,
    TransportAuth,
    OpaqueRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAction {
    BoundedRetrySamePin,
    ReconcileUnknown,
    RequalifyNewPin,
    FenceHaltRecordRequalify,
    DoNotRunNewPinRevision,
    FixCredentialOrConfig,
    RemoveAutoRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureDisposition {
    pub evidence: super::status::EvidenceState,
    pub item_blocked: bool,
    pub action: FailureAction,
    /// Primary never-paid clause; the full row may carry more than one.
    pub never_paid: super::status::NeverPaidInvariant,
}

impl PinFailure {
    pub fn not_run_reason(self) -> super::status::NotRunReason {
        use super::status::NotRunReason as R;
        match self {
            Self::QuotaBeforeInference => R::Availability,
            Self::QuotaAfterInference => R::UnknownOutcome,
            Self::ModelRetired => R::ModelRetired,
            Self::ProviderFallback => R::ProviderSubstitution,
            Self::ServedIdentityMissing => R::ServedIdentityMissing,
            Self::ServedIdentityMismatch => R::ServedIdentityMismatch,
            Self::MidSessionDivergence => R::MidSessionDivergence,
            Self::LocalDigestMismatch => R::LocalDigestMismatch,
            Self::TransportAuth => R::TransportAuth,
            Self::OpaqueRoute => R::OpaqueRoute,
        }
    }

    /// Every row is NOT RUN + BLOCKED + a never-paid clause; no row is PASS.
    pub fn disposition(self) -> FailureDisposition {
        use super::status::NeverPaidInvariant as N;
        let (action, never_paid) = match self {
            Self::QuotaBeforeInference => (FailureAction::BoundedRetrySamePin, N::NoPaidRoute),
            Self::QuotaAfterInference => (FailureAction::ReconcileUnknown, N::NoSubstituteModel),
            Self::ModelRetired => (FailureAction::RequalifyNewPin, N::NoSuccessorInheritance),
            Self::ProviderFallback => (FailureAction::RequalifyNewPin, N::NoProviderFallback),
            Self::ServedIdentityMissing => (FailureAction::RequalifyNewPin, N::NoSubstituteModel),
            Self::ServedIdentityMismatch => (
                FailureAction::FenceHaltRecordRequalify,
                N::NoSubstituteModel,
            ),
            Self::MidSessionDivergence => (
                FailureAction::FenceHaltRecordRequalify,
                N::NoMidSessionReroute,
            ),
            Self::LocalDigestMismatch => {
                (FailureAction::DoNotRunNewPinRevision, N::NoUnverifiedBuild)
            }
            Self::TransportAuth => (
                FailureAction::FixCredentialOrConfig,
                N::NoCredentialOrModelEscalation,
            ),
            Self::OpaqueRoute => (FailureAction::RemoveAutoRoute, N::NoRotatingRouter),
        };
        FailureDisposition {
            evidence: super::status::EvidenceState::NotRun,
            item_blocked: true,
            action,
            never_paid,
        }
    }

    /// `QuotaAfterInference` may also have bought credit; the mapping keeps the
    /// primary clause and the table's secondary clause is documented in C6.
    pub fn never_paid_clauses(self) -> Vec<super::status::NeverPaidInvariant> {
        use super::status::NeverPaidInvariant as N;
        match self {
            Self::QuotaBeforeInference => vec![N::NoPaidRoute, N::NoCreditPurchase],
            other => vec![other.disposition().never_paid],
        }
    }
}

// ---------------------------------------------------------------------------
// Errors (C6 §7.6)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("capability {0:?} is unavailable")]
    CapabilityUnavailable(CapabilityId),
    #[error("manifest {0:?} is invalid")]
    ManifestInvalid(ManifestId),
    #[error("manifest {0:?} is not current")]
    ManifestNotCurrent(ManifestId),
    #[error("conditional capability has no condition")]
    ConditionalWithoutCondition,
    #[error("private-serve path is not qualified")]
    PrivateServeUnqualified,
    #[error("canary record is invalid: {0}")]
    CanaryInvalid(CanaryError),
    #[error("PASS without machine evidence is forbidden")]
    PassWithoutMachineEvidence,
    #[error("dispatch binding is invalid")]
    BindingInvalid(super::dispatch::DispatchBindingError),
    #[error("dispatch denied: {0:?}")]
    DispatchDenied(DispatchDenial),
    #[error("environment allowlist is invalid")]
    EnvironmentInvalid(EnvironmentError),
    #[error("permission policy is malformed")]
    PermissionPolicyMalformed,
    #[error("a credential value was supplied where a reference is required")]
    SecretValueNotAllowed,
    #[error("model pin is invalid: {0}")]
    PinInvalid(super::pin::PinError),
    #[error("payload exceeds {limit} bytes")]
    Oversize { limit: usize },
    #[error("malformed adapter payload")]
    Malformed,
    #[error("adapter operation is not implemented in Phase B")]
    PhaseBNotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchDenial {
    D27CertificateAbsent,
    D27CertificateStale,
    D27FingerprintMismatch,
    WorkerTaskBindingMissing,
    CapabilityUnavailable,
    CanaryNotPass,
    PhaseBNotImplemented,
}

#[derive(Debug, thiserror::Error)]
pub enum CanaryError {
    #[error("PASS requires final-tool inventory or complete-unavailable proof")]
    PassWithoutMachineEvidence,
    #[error("NOT RUN requires a reason")]
    NotRunWithoutReason,
    #[error("canary evidence is insufficient: {0:?}")]
    Insufficient(CanaryEvidenceGap),
    #[error("canary is not bound to the current pin/manifest/policy")]
    StaleBinding,
    #[error("private serve is not qualified")]
    PrivateServeUnqualified,
}

#[derive(Debug, thiserror::Error)]
pub enum NdjsonError {
    #[error("line exceeds 1 MiB")]
    Oversize,
    #[error("invalid UTF-8")]
    InvalidUtf8,
    #[error("invalid JSON")]
    InvalidJson,
    #[error("ANSI control sequence in a record")]
    Ansi,
    #[error("multiline record")]
    Multiline,
    #[error("non-finite or negative numeric field")]
    InvalidNumber,
    #[error("duplicate usage step for the same key")]
    DuplicateUsage,
    #[error("redaction failed")]
    RedactionFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum EnvironmentError {
    #[error("environment name is invalid")]
    InvalidName,
    #[error("literal value contains a forbidden control character")]
    InvalidLiteral,
    #[error("a secret value was supplied instead of a reference")]
    SecretValue,
    #[error("environment fingerprint could not be computed")]
    Fingerprint,
    #[error("permission policy is malformed")]
    MalformedPermissionPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxSource {
    Trello,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct InboxKey(pub SafeCode);
