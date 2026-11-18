//! C4 state API: the only mutation/read surface Track 2 may use.
//!
//! One dedicated writer thread owns the only `rusqlite::Connection`; audit and
//! outbox intents commit atomically with state (LLD §3 lines 109–198).

use std::collections::HashSet;

use super::adapter::PinFailure;
use super::audit::{AuditEventDraft, AuditHead};
use super::doctor::AdapterSessionRecord;
use super::primitives::{
    AdmissionId, ApprovalId, AttemptId, AuditSequence, BranchName, CanaryId, CertificateId,
    DaemonGeneration, DispatchId, DispatchOrdinal, EvidenceId, Fence, FingerprintDigest, GitSha,
    JobGeneration, LeaseId, ManifestId, OutboxId, OutboxKey, ProcessRecordId, Revision, SafeId,
    SessionId, Sha256Digest, StateRequestId, TaskId, UtcMillis, WindowsAbsolutePath,
};
use super::process::{ProcessIdentity, RecoveryReason, TerminationProofEvidence};
use super::schema::SchemaVersion;
use super::status::{
    AttemptState, DaemonGenerationState, DispatchIntentState, DispatchState, EvidenceRecord,
    ProcessObservedState, TaskState,
};

// ---------------------------------------------------------------------------
// Traits (C4 §5.1)
// ---------------------------------------------------------------------------

pub trait StateWriter: Send + Sync {
    fn submit(
        &self,
        txn: StateTxn,
    ) -> super::primitives::BoxFuture<'_, Result<CommitReceipt, StateError>>;
}

pub trait StateReader: Send + Sync {
    fn read(
        &self,
        query: StateQuery,
    ) -> super::primitives::BoxFuture<'_, Result<StateReply, StateError>>;
}

/// A validated all-or-nothing transaction envelope. Construct with
/// [`StateTxn::new`]; fields are private so audit/outbox cannot be committed
/// separately by mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTxn {
    request_id: StateRequestId,
    generation: DaemonGeneration,
    submitted_at_ms: UtcMillis,
    mutations: Vec<StateMutation>,
    audit: Vec<AuditEventDraft>,
    outbox: Vec<OutboxIntent>,
}

impl StateTxn {
    pub fn new(
        request_id: StateRequestId,
        generation: DaemonGeneration,
        submitted_at_ms: UtcMillis,
        mutations: Vec<StateMutation>,
        audit: Vec<AuditEventDraft>,
        outbox: Vec<OutboxIntent>,
    ) -> Result<Self, StateError> {
        if mutations.is_empty() && audit.is_empty() && outbox.is_empty() {
            return Err(StateError::EmptyTransaction);
        }
        let mut targets = HashSet::new();
        for mutation in &mutations {
            if !targets.insert(mutation.target.clone()) {
                return Err(StateError::DuplicateTarget(mutation.target.clone()));
            }
        }
        let txn = Self {
            request_id,
            generation,
            submitted_at_ms,
            mutations,
            audit,
            outbox,
        };
        if txn.estimated_bytes() > super::channel::MAX_STATE_TXN_BYTES {
            return Err(StateError::TransactionTooLarge {
                limit: super::channel::MAX_STATE_TXN_BYTES,
            });
        }
        Ok(txn)
    }

    pub fn request_id(&self) -> &StateRequestId {
        &self.request_id
    }

    pub fn generation(&self) -> DaemonGeneration {
        self.generation
    }

    pub fn submitted_at_ms(&self) -> UtcMillis {
        self.submitted_at_ms
    }

    pub fn mutations(&self) -> &[StateMutation] {
        &self.mutations
    }

    pub fn audit(&self) -> &[AuditEventDraft] {
        &self.audit
    }

    pub fn outbox(&self) -> &[OutboxIntent] {
        &self.outbox
    }

    /// Conservative upper bound before encoding. Evidence content stays on
    /// disk; only digests/paths/sizes enter the transaction. Exact accounting
    /// is Track 1's (PM decision D4).
    pub fn estimated_bytes(&self) -> usize {
        self.mutations.len() * 1024 + self.audit.len() * 2048 + self.outbox.len() * 1024
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateMutation {
    pub target: StateTarget,
    pub expected_revision: Option<Revision>,
    pub op: StateOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StateTarget {
    DaemonGeneration,
    Attempt(AttemptId),
    Dispatch(DispatchId),
    Task(TaskId),
    Lease(LeaseId),
    OwnedProcess(ProcessRecordId),
    Evidence(EvidenceId),
    Outbox(OutboxId),
    Approval(ApprovalId),
    AuditChain,
    Session(SessionId),
}

/// No `AppendOutbox` op: outbox intents travel only in `StateTxn.outbox`
/// (PM decision P1-13) so one intent cannot commit twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateOp {
    BeginDaemonGeneration {
        started_at_ms: UtcMillis,
    },
    MarkCleanShutdown {
        at: UtcMillis,
    },
    RecordLaunchIntent {
        dispatch_id: DispatchId,
        attempt_id: AttemptId,
        admission_id: AdmissionId,
        manifest_id: ManifestId,
        canary_id: CanaryId,
        lease_id: Option<LeaseId>,
        fence: Fence,
        intent_state: DispatchIntentState,
    },
    RecordProcessIdentity {
        dispatch_id: DispatchId,
        identity: ProcessIdentity,
        executable_digest: Sha256Digest,
        job_generation: JobGeneration,
        observed_state: ProcessObservedState,
    },
    UpdateOwnedProcessState {
        observed_state: ProcessObservedState,
    },
    TransitionAttempt {
        from: AttemptState,
        to: AttemptState,
    },
    TransitionDispatch {
        from: DispatchState,
        to: DispatchState,
    },
    TransitionTask {
        from: TaskState,
        to: TaskState,
    },
    ParkRecoveryRequired {
        reason: RecoveryReason,
        finding: super::primitives::RecoveryFindingId,
    },
    InsertEvidence {
        evidence: EvidenceRecord,
    },
    RecordTerminationProof {
        proof: TerminationProofEvidence,
    },
    ConsumeGrant {
        approval_id: ApprovalId,
        action_id: super::primitives::ActionId,
        consumed_at_ms: UtcMillis,
    },
    RecordInbox {
        source: super::adapter::InboxSource,
        key: super::adapter::InboxKey,
        digest: Sha256Digest,
        aggregate_sequence: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReceipt {
    pub request_id: StateRequestId,
    pub generation: DaemonGeneration,
    pub committed_at_ms: UtcMillis,
    /// Present iff at least one audit draft was appended.
    pub audit_sequence: Option<AuditSequence>,
    pub audit_head: AuditHead,
    pub revisions: Vec<ObjectRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRevision {
    pub target: StateTarget,
    pub revision: Revision,
}

// ---------------------------------------------------------------------------
// Queries (C4 §5.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateQuery {
    CurrentOwnership,
    RecoveryView {
        generation: DaemonGeneration,
    },
    DispatchView {
        dispatch_id: DispatchId,
    },
    AttemptView {
        attempt_id: AttemptId,
    },
    AuditHead,
    ReadinessCertificate {
        certificate_id: CertificateId,
        input_fingerprint: FingerprintDigest,
    },
    OutboxView {
        outbox_id: OutboxId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateReply {
    CurrentOwnership(DaemonOwnership),
    RecoveryView(RecoveryView),
    DispatchView(DispatchView),
    AttemptView(AttemptView),
    AuditHead(AuditHead),
    ReadinessCertificate(super::certificate::CertificateVerdict),
    OutboxView(OutboxView),
}

/// Typed records mirroring the designed tables — never free-form rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryView {
    pub generation: DaemonGeneration,
    pub daemon: DaemonGenerationRecord,
    pub launch_intents: Vec<LaunchIntentRecord>,
    pub owned_processes: Vec<OwnedProcessRecord>,
    pub leases: Vec<LeaseRecord>,
    pub attempts: Vec<AttemptRecord>,
    pub dispatches: Vec<DispatchRecord>,
    /// Added by PM decision P1-4 so Doctor can reconcile adapter sessions.
    pub adapter_sessions: Vec<AdapterSessionRecord>,
    pub audit_head: AuditHead,
    pub pending_outbox: Vec<OutboxRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonGenerationRecord {
    pub generation: DaemonGeneration,
    pub started_at_ms: UtcMillis,
    pub clean_shutdown: bool,
    pub state: DaemonGenerationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchIntentRecord {
    pub dispatch_id: DispatchId,
    pub attempt_id: AttemptId,
    pub admission_id: AdmissionId,
    pub fence: Fence,
    pub intent_state: DispatchIntentState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProcessRecord {
    pub process_record_id: ProcessRecordId,
    pub dispatch_id: DispatchId,
    pub identity: Option<ProcessIdentity>,
    pub executable_digest: Sha256Digest,
    pub job_generation: JobGeneration,
    pub observed_state: ProcessObservedState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRecord {
    pub lease_id: LeaseId,
    pub attempt_id: AttemptId,
    pub kind: LeaseKind,
    pub scope: LeaseScope,
    pub generation: DaemonGeneration,
    pub fence: Fence,
    pub state: LeaseState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseKind {
    Scratch,
    Implementation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseScope {
    ScratchDirectory(WindowsAbsolutePath),
    Repository {
        worktree: WindowsAbsolutePath,
        branch: BranchName,
        base_sha: GitSha,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    Reserved,
    Active,
    RecoveryHeld,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRecord {
    pub attempt_id: AttemptId,
    pub state: AttemptState,
    pub retry_count: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchRecord {
    pub dispatch_id: DispatchId,
    pub attempt_id: AttemptId,
    pub ordinal: DispatchOrdinal,
    pub binding_kind: super::dispatch::BindingKind,
    pub state: DispatchState,
    pub session_id: Option<SessionId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRecord {
    pub outbox_id: OutboxId,
    pub destination: OutboxDestination,
    pub key: OutboxKey,
    pub aggregate_sequence: u64,
    pub state: OutboxState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxView {
    pub intent: OutboxIntent,
    pub last_observed_at: Option<UtcMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchView {
    pub record: DispatchRecord,
    pub intent: Option<DispatchIntentState>,
    pub session: Option<SessionId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptView {
    pub record: AttemptRecord,
    pub active_dispatch: Option<DispatchId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxIntent {
    pub outbox_id: OutboxId,
    pub destination: OutboxDestination,
    pub key: OutboxKey,
    pub aggregate_sequence: u64,
    pub payload_digest: Sha256Digest,
    pub state: OutboxState,
}

/// `Fake` is test-only (PM decision §G.1) and never a production value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxDestination {
    Trello,
    #[cfg(any(test, feature = "test-support"))]
    Fake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    Pending,
    InFlight,
    Acknowledged,
    Failed,
    Unknown,
}

// ---------------------------------------------------------------------------
// Ownership and certificate verdict (C6 §7.7)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonOwnership {
    pub generation: DaemonGeneration,
    pub previous_generation: Option<DaemonGeneration>,
    pub previous_clean_shutdown: Option<bool>,
    pub schema: SchemaVersion,
}

// ---------------------------------------------------------------------------
// Errors (C4 §5.4)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state writer is unavailable")]
    WriterUnavailable,
    #[error("state channel is full; capacity {capacity}")]
    Backpressure { capacity: usize },
    #[error("state transaction exceeds {limit} bytes")]
    TransactionTooLarge { limit: usize },
    #[error("state transaction has no mutations, audit or outbox intents")]
    EmptyTransaction,
    #[error("duplicate state target {0:?} without an explicit order")]
    DuplicateTarget(StateTarget),
    #[error("expected revision {expected:?} for {target:?}, found {actual:?}")]
    Conflict {
        target: StateTarget,
        expected: Revision,
        actual: Revision,
    },
    #[error("daemon generation {found:?} is not current (expected {expected:?})")]
    NotCurrentGeneration {
        expected: DaemonGeneration,
        found: DaemonGeneration,
    },
    #[error("schema {found:?} is newer than supported {supported:?}")]
    SchemaNewer {
        found: SchemaVersion,
        supported: SchemaVersion,
    },
    #[error("migration {migration:?} checksum does not match")]
    MigrationChecksumMismatch {
        migration: super::schema::MigrationId,
    },
    #[error("foreign key constraint {constraint} failed")]
    ForeignKeyViolation { constraint: &'static str },
    #[error("constraint {constraint} failed")]
    ConstraintViolation { constraint: &'static str },
    #[error("object {target:?} was not found")]
    NotFound { target: StateTarget },
    #[error("invalid transition {from} -> {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("state is in recovery_required: {reason:?}")]
    RecoveryRequired { reason: RecoveryReason },
    #[error("audit chain is unavailable")]
    AuditChainUnavailable,
    #[error("encoding failed for {field}")]
    Encode { field: &'static str },
    #[error("internal state error {code:?}")]
    Internal {
        code: super::schema::InternalErrorCode,
    },
}

impl StateError {
    /// A pin failure is recorded as NOT RUN with its reason, never a state
    /// error; this conversion exists so callers cannot lose the reason.
    pub fn not_run_reason(failure: PinFailure) -> super::status::NotRunReason {
        failure.not_run_reason()
    }
}

/// State request ids are opaque; this helper keeps test code from inventing
/// display-name identities.
pub fn request_id(value: &str) -> Result<StateRequestId, super::primitives::IdError> {
    StateRequestId::new(value.to_owned())
}

/// Safe id alias used by the daemon composition root for store identity.
pub type StoreId = SafeId;
