//! Typed, read-only Doctor (PM decision D2). It never writes, kills or cleans.

use super::audit::AuditHead;
use super::primitives::{
    AttemptId, BranchName, DaemonGeneration, EvidenceId, GitSha, SafeId, SessionId, UtcMillis,
    WindowsAbsolutePath,
};
use super::process::{ProcessEnumeration, ProcessObservation, ProofUnavailableReason};
use super::state::{LeaseRecord, OutboxRecord, OwnedProcessRecord, RecoveryView};
use super::status::{BlockCondition, ObjectRef};

pub trait Doctor: Send + Sync {
    fn reconcile(
        &self,
        view: RecoveryView,
        probes: &dyn DoctorProbes,
    ) -> super::primitives::BoxFuture<'_, Result<DoctorReport, DoctorError>>;
}

pub trait DoctorProbes: Send + Sync {
    fn process_identity(
        &self,
        record: &OwnedProcessRecord,
    ) -> super::primitives::BoxFuture<'_, Result<ProcessObservation, ProbeError>>;
    fn job_membership(
        &self,
        record: &OwnedProcessRecord,
    ) -> super::primitives::BoxFuture<'_, Result<JobObservation, ProbeError>>;
    fn worktree_status(
        &self,
        lease: &LeaseRecord,
    ) -> super::primitives::BoxFuture<'_, Result<WorktreeObservation, ProbeError>>;
    fn outbox_outcome(
        &self,
        record: &OutboxRecord,
    ) -> super::primitives::BoxFuture<'_, Result<OutboxObservation, ProbeError>>;
    fn adapter_session(
        &self,
        record: &AdapterSessionRecord,
    ) -> super::primitives::BoxFuture<'_, Result<AdapterSessionObservation, ProbeError>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobObservation {
    /// The Job handle is still open and enumeration succeeded.
    Enumerated(ProcessEnumeration),
    /// After a restart the unnamed Job cannot be reopened.
    Unavailable { reason: ProofUnavailableReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeObservation {
    pub path: WindowsAbsolutePath,
    pub branch: BranchName,
    pub base_sha: GitSha,
    pub dirty: bool,
    pub checked_at_ms: UtcMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxObservation {
    pub outcome: OutboxObservationOutcome,
    pub observed_at_ms: UtcMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxObservationOutcome {
    NotSent,
    SentKnown,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterSessionObservation {
    pub session_id: Option<SessionId>,
    pub export_state: AdapterExportState,
    pub observed_at_ms: UtcMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterExportState {
    NotExported,
    ExportedVerified,
    ExportUnknown,
    StoreMissing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterSessionRecord {
    pub store_id: SafeId,
    pub attempt_id: AttemptId,
    pub absolute_identity: WindowsAbsolutePath,
    pub session_id: Option<SessionId>,
    pub export_state: AdapterExportState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub generation: DaemonGeneration,
    pub observed_at_ms: UtcMillis,
    pub findings: Vec<DoctorFinding>,
    pub status: DoctorStatus,
    pub audit_head: AuditHead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorStatus {
    Clean,
    Findings,
    Blocked,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorFinding {
    pub object: ObjectRef,
    pub kind: DoctorFindingKind,
    pub disposition: DoctorDisposition,
    pub reason: DoctorReason,
    pub evidence_ref: Option<EvidenceId>,
    pub block: Option<BlockCondition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DoctorFindingKind {
    DaemonGeneration,
    LaunchIntent,
    OwnedProcess,
    Lease,
    Worktree,
    CheckResult,
    Review,
    Approval,
    Outbox,
    Inbox,
    AdapterSession,
    Schema,
    Audit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorDisposition {
    KnownComplete,
    KnownAbsent,
    Retained,
    RecoveryRequired,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DoctorReason {
    NoLaunchIntent,
    LaunchIntentWithoutProcess,
    ProcessIdentityMismatch,
    ProcessAbsent,
    JobUnavailableAfterRestart,
    OutputExpired,
    LeaseUncertain,
    WorktreeDirty,
    CheckExpired,
    ReviewInvalidated,
    ApprovalExpired,
    OutboxUnknown,
    InboxConflict,
    AdapterSessionUnreconciled,
    SchemaUnreadable,
    AuditUnavailable,
    GenerationUnclean,
    UnknownOwnership,
    ProbeUnavailable,
}

#[derive(Debug, thiserror::Error)]
pub enum DoctorError {
    #[error("doctor probe failed: {0:?}")]
    Probe(ProbeError),
    #[error("recovery view is inconsistent")]
    InconsistentView,
    #[error("doctor cannot decide: {0:?}")]
    Undecidable(DoctorReason),
    #[error("doctor writes are forbidden")]
    WriteForbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    Unsupported,
    AccessDenied { code: u32 },
    Timeout,
    QueryFailed { code: u32 },
    NotFound,
    Unknown,
}

impl DoctorReport {
    /// `Clean` only when every expected record has a known finding, no block
    /// is required, and the audit head was readable. An empty list is not
    /// automatically clean.
    pub fn is_clean(&self) -> bool {
        self.status == DoctorStatus::Clean
            && !self.findings.is_empty()
            && self.findings.iter().all(|finding| {
                matches!(
                    finding.disposition,
                    DoctorDisposition::KnownComplete | DoctorDisposition::KnownAbsent
                ) && finding.block.is_none()
            })
    }

    /// Deterministic order: `(kind, object, reason)`.
    pub fn sort_findings(&mut self) {
        self.findings.sort_by(|left, right| {
            (left.kind, format!("{:?}", left.object), left.reason).cmp(&(
                right.kind,
                format!("{:?}", right.object),
                right.reason,
            ))
        });
    }
}
