//! C6 status and error taxonomy (D29 as two axes, never one enum).

use serde::{Deserialize, Serialize};

use super::audit::AuditActor;
use super::primitives::{
    AttemptId, DaemonGeneration, DispatchId, EvidenceId, GoalId, LeaseId, ProcessRecordId,
    RedactionVersion, Revision, SafeCode, SafeRelativePath, Sha256Digest, TaskId, UtcMillis,
};
use super::process::RecoveryReason;

// ---------------------------------------------------------------------------
// Evidence: exactly PASS / FAIL / NOT RUN (C6 §7.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Pass,
    Fail,
    NotRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStatus {
    pub state: EvidenceState,
    /// Present exactly when `state == NotRun` (D29).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_run_reason: Option<NotRunReason>,
    /// Optional safe failure code for `Fail`; never a substitute for evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<SafeCode>,
}

impl EvidenceStatus {
    pub fn pass() -> Self {
        Self {
            state: EvidenceState::Pass,
            not_run_reason: None,
            failure_code: None,
        }
    }

    pub fn fail(code: Option<SafeCode>) -> Self {
        Self {
            state: EvidenceState::Fail,
            not_run_reason: None,
            failure_code: code,
        }
    }

    pub fn not_run(reason: NotRunReason) -> Self {
        Self {
            state: EvidenceState::NotRun,
            not_run_reason: Some(reason),
            failure_code: None,
        }
    }

    pub fn validate(&self) -> Result<(), StatusError> {
        match self.state {
            EvidenceState::Pass | EvidenceState::Fail if self.not_run_reason.is_some() => {
                Err(StatusError::ReasonOnNonNotRun)
            }
            EvidenceState::NotRun if self.not_run_reason.is_none() => {
                Err(StatusError::NotRunWithoutReason)
            }
            _ => Ok(()),
        }
    }

    /// Only a validated PASS may be presented as acceptance evidence.
    pub fn is_pass(&self) -> bool {
        self.state == EvidenceState::Pass && self.validate().is_ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotRunReason {
    Availability,
    UnknownOutcome,
    ModelRetired,
    ProviderSubstitution,
    ServedIdentityMissing,
    ServedIdentityMismatch,
    MidSessionDivergence,
    LocalDigestMismatch,
    TransportAuth,
    OpaqueRoute,
    CanaryEvidenceIncomplete,
    CapabilityUnverified,
    D27CertificateAbsent,
    MalformedPolicy,
    SchemaUnknown,
    PlatformUnsupported,
    FixtureOnly,
    PhaseBNotImplemented,
}

impl NotRunReason {
    /// `FixtureOnly` is constructible in test-support code only; when recorded
    /// it can never be a product acceptance result.
    pub const fn is_product_eligible(self) -> bool {
        !matches!(self, Self::FixtureOnly | Self::PhaseBNotImplemented)
    }
}

// ---------------------------------------------------------------------------
// Lifecycle states (C6 §7.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalPhase {
    Discovery,
    Architecture,
    Planning,
    Executing,
    Integrating,
    AwaitingAcceptance,
    Blocked,
    Accepted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Planned,
    Ready,
    Running,
    Verifying,
    Reviewing,
    RepairPending,
    VerifiedHandoff,
    Integrating,
    Blocked,
    RecoveryRequired,
    IntegratedClosed,
    Withdrawn,
    Cancelled,
}

impl TaskState {
    /// Only these three task states are terminal.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::IntegratedClosed | Self::Withdrawn | Self::Cancelled
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonGenerationState {
    Starting,
    Running,
    CleanStopped,
    UncleanStopped,
    OwnershipUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Reserved,
    LaunchIntent,
    Running,
    Verifying,
    Reviewing,
    Succeeded,
    Failed,
    CancelPending,
    Cancelled,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchState {
    Reserved,
    LaunchIntent,
    Running,
    Cancelling,
    Cancelled,
    Succeeded,
    Failed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchIntentState {
    Recorded,
    Spawned,
    IdentityObserved,
    Active,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessObservedState {
    Unknown,
    Running,
    Exited,
    TerminationPending,
    Terminated,
    RecoveryRequired,
}

// ---------------------------------------------------------------------------
// Evidence record and proof type (C6 §7.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub evidence_id: EvidenceId,
    pub artefact: SafeArtifactRef,
    pub evidence_type: EvidenceType,
    pub producer: AuditActor,
    pub revision: Revision,
    pub redaction_version: RedactionVersion,
    pub integrity: EvidenceIntegrity,
    pub created_at_ms: UtcMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    TerminationProof,
    Canary,
    ServedIdentity,
    CapabilityQualification,
    SanitizedExport,
    Other(SafeCode),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeArtifactRef {
    /// Relative to the evidence root; no absolute path, drive, `..` or NUL.
    pub relative_path: SafeRelativePath,
    pub digest: Sha256Digest,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceIntegrity {
    Verified,
    Missing,
    HashMismatch,
    Unavailable,
}

impl EvidenceRecord {
    /// Only `Verified` evidence may support a PASS (LLD §3 line 148).
    pub fn supports_pass(&self) -> bool {
        self.integrity == EvidenceIntegrity::Verified
    }
}

// ---------------------------------------------------------------------------
// Recovery signal vs block condition (C6 §7.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySignal {
    pub object: ObjectRef,
    pub reason: RecoveryReason,
    pub block: BlockCondition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObjectRef {
    Goal(GoalId),
    Task(TaskId),
    Attempt(AttemptId),
    Dispatch(DispatchId),
    Lease(LeaseId),
    Process(ProcessRecordId),
    Evidence(EvidenceId),
    Daemon(DaemonGeneration),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockCondition {
    pub owner: BlockOwner,
    pub reason: BlockReason,
    pub unblock: UnblockCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockOwner {
    Owner,
    ProjectManager,
    Daemon,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    Quota,
    UnknownEffect,
    ModelRetired,
    ProviderSubstitution,
    IdentityUnavailable,
    IdentityMismatch,
    MidSessionDivergence,
    LocalDigestMismatch,
    CredentialOrConfig,
    OpaqueRoute,
    CapabilityUnavailable,
    D27Unavailable,
    SchemaUnknown,
    OwnershipUnknown,
    LeaseUncertain,
    TerminationUnproven,
    PolicyDecisionPending,
    PlatformUnsupported,
    FixtureOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnblockCondition {
    BoundedRetrySamePin,
    ReconcileUnknownOutcome,
    NewPinRevision,
    OwnerPinDecision,
    OwnerPolicyDecision,
    FixCredentialOrConfig,
    RemoveAutoRoute,
    RestoreAuthoritativeState,
    CurrentOwnedProcessProof,
    FreshD27Certificate,
    ProvideSupportedPlatform,
    NoAutomaticUnblock,
}

// ---------------------------------------------------------------------------
// Never-paid invariant (9 clauses, C6 §7.5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeverPaidInvariant {
    NoPaidRoute,
    NoCreditPurchase,
    NoSubstituteModel,
    NoProviderFallback,
    NoSuccessorInheritance,
    NoMidSessionReroute,
    NoUnverifiedBuild,
    NoCredentialOrModelEscalation,
    NoRotatingRouter,
}

#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    #[error("NOT RUN requires a reason")]
    NotRunWithoutReason,
    #[error("a non-NOT RUN status cannot carry a not_run_reason")]
    ReasonOnNonNotRun,
    #[error("invalid state transition")]
    InvalidTransition,
}
