//! C1 `OwnedProcess` boundary and C2 process identity / termination proof.
//!
//! Design sources: HLD §5 lines 86–94; LLD §1 line 24; LLD §3 lines 139, 188–192.
//! Contracts only: no spawner, Job or process implementation lives here.

use std::time::Duration;
use tokio::io::AsyncRead;

pub use super::primitives::BoxFuture;
use super::primitives::{
    CreationFiletime, DaemonGeneration, DispatchId, JobGeneration, Sha256Digest, UtcMillis,
    WindowsAbsolutePath,
};

// ---------------------------------------------------------------------------
// C1 — owned spawn boundary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableRef {
    pub path: WindowsAbsolutePath,
    pub digest: Sha256Digest,
    pub version: Option<super::pin::AdapterVersion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioMode {
    Piped,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdioPlan {
    pub stdin: StdioMode,
    pub stdout: StdioMode,
    pub stderr: StdioMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedSpawnSpec {
    pub dispatch_id: DispatchId,
    pub attempt_id: super::primitives::AttemptId,
    pub daemon_generation: DaemonGeneration,
    pub job_generation: JobGeneration,
    pub executable: ExecutableRef,
    /// Each element is one argv element; the spawner performs Win32 quoting and
    /// never interpolates a shell string.
    pub arguments: Vec<String>,
    pub working_directory: WindowsAbsolutePath,
    pub environment: super::adapter::EnvironmentAllowlist,
    pub stdio: StdioPlan,
}

pub trait OwnedProcess: Send + 'static {
    fn identity(&self) -> &ProcessIdentity;
    fn job_generation(&self) -> JobGeneration;

    fn take_stdout(&mut self) -> Result<Box<dyn AsyncRead + Send + Unpin>, ProcessError>;
    fn take_stderr(&mut self) -> Result<Box<dyn AsyncRead + Send + Unpin>, ProcessError>;

    /// Resolves when the root process exits. This is not tree termination.
    fn wait_root(&mut self) -> BoxFuture<'_, Result<RootExit, ProcessError>>;

    /// Enumerates the processes in this dispatch's owned Job.
    fn enumerate(&self) -> BoxFuture<'_, Result<ProcessEnumeration, ProcessError>>;

    /// Terminates only the owned Job and returns the independent proof attempt.
    fn terminate_owned(
        &mut self,
        deadline: Duration,
    ) -> BoxFuture<'_, Result<TerminationProof, ProcessError>>;

    /// Closes the Job/process handles. It is not a proof of termination.
    fn close(self: Box<Self>) -> Result<(), ProcessError>;
}

pub trait OwnedProcessSpawner: Send + Sync {
    fn spawn(
        &self,
        spec: OwnedSpawnSpec,
    ) -> BoxFuture<'_, Result<Box<dyn OwnedProcess>, ProcessError>>;
}

// ---------------------------------------------------------------------------
// C2 — identity, enumeration, proof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub creation_filetime: CreationFiletime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessObservation {
    pub identity: ProcessIdentity,
    pub executable_digest: Sha256Digest,
    pub observed_at_ms: UtcMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumerationCompleteness {
    Complete,
    Partial { reason: EnumerationLimit },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumerationLimit {
    QueryFailed { code: u32 },
    Timeout,
    AccessDenied,
    ListTruncated,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEnumeration {
    pub observed_at_ms: UtcMillis,
    pub identities: Vec<ProcessIdentity>,
    pub active_processes: u32,
    pub completeness: EnumerationCompleteness,
}

impl ProcessEnumeration {
    /// C5/C2 canonical order: `(pid, creation_filetime)` ascending.
    pub fn sort_identities(&mut self) {
        self.identities
            .sort_by_key(|id| (id.pid, id.creation_filetime.0));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootExit {
    pub identity: ProcessIdentity,
    pub exit_code: Option<u32>,
    pub observed_at_ms: UtcMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserverIdentity {
    /// The daemon's own supervisor, bound to the daemon generation.
    Supervisor { generation: DaemonGeneration },
    /// An independent qualification observer. It may retain process handles;
    /// it must never retain the Job handle (HLD §5 line 94).
    Qualification {
        process: ProcessIdentity,
        executable_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofLimitation {
    PostRestartJobHandleUnavailable,
    KernelKillOnCloseReliedUpon,
    BrokerDescendantsNotContained,
    ObserverCannotEnumerate,
    ProcessAccountingNotReported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationProof {
    pub dispatch_id: DispatchId,
    pub job_generation: JobGeneration,
    pub root: ProcessIdentity,
    pub root_signalled: bool,
    pub enumeration: ProcessEnumeration,
    pub observer: ObserverIdentity,
    pub observed_at_ms: UtcMillis,
    pub limitations: Vec<ProofLimitation>,
}

impl TerminationProof {
    /// P1-7: a limitation blocks `ConfirmedComplete` only when it prevents
    /// observation. `KernelKillOnCloseReliedUpon` is recorded but never a
    /// substitute for a complete, empty enumeration.
    pub fn blocks_complete(&self) -> bool {
        self.limitations.iter().any(|l| {
            matches!(
                l,
                ProofLimitation::PostRestartJobHandleUnavailable
                    | ProofLimitation::BrokerDescendantsNotContained
                    | ProofLimitation::ObserverCannotEnumerate
                    | ProofLimitation::ProcessAccountingNotReported
            )
        })
    }

    /// True only for: root signalled, complete enumeration, empty identity
    /// list, zero active accounting, and no blocking limitation (C2 §3.2).
    pub fn is_complete(&self) -> bool {
        self.root_signalled
            && self.enumeration.completeness == EnumerationCompleteness::Complete
            && self.enumeration.identities.is_empty()
            && self.enumeration.active_processes == 0
            && !self.blocks_complete()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationAck {
    pub dispatch_id: DispatchId,
    pub acknowledged_at_ms: UtcMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationStatus {
    ConfirmedComplete,
    NotYetComplete {
        root_signalled: bool,
        active_processes: u32,
    },
    Unavailable {
        reason: ProofUnavailableReason,
    },
    RecoveryRequired {
        reason: RecoveryReason,
    },
}

impl TerminationStatus {
    /// Only a complete proof yields `ConfirmedComplete` (P1-7 / D5 rule 2).
    pub fn from_proof(proof: &TerminationProof) -> Self {
        if proof.is_complete() {
            Self::ConfirmedComplete
        } else if proof.enumeration.completeness != EnumerationCompleteness::Complete {
            Self::RecoveryRequired {
                reason: RecoveryReason::TerminationUnproven,
            }
        } else {
            Self::NotYetComplete {
                root_signalled: proof.root_signalled,
                active_processes: proof.enumeration.active_processes,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationOutcome {
    pub ack: CancellationAck,
    pub proof: Option<TerminationProof>,
    pub status: TerminationStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofUnavailableReason {
    PostRestart,
    QueryTimeout,
    QueryFailed { code: u32 },
    JobHandleClosed,
    PlatformUnsupported,
    ObserverUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReason {
    TerminationUnproven,
    EnumerationTimedOut,
    AccountingNonZero,
    ProcessQueryFailed,
    ProcessIdentityUnknown,
    ProcessIdentityMismatch,
    EffectOutcomeUnknown,
    AuditChainUnavailable,
    SchemaOwnershipUnknown,
    SchemaUnreadable,
    UnknownOwnership,
    LaunchIntentWithoutProcess,
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
    GenerationUnclean,
}

// ---------------------------------------------------------------------------
// Errors (C1/C2/C6)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("owned spawn is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("owned spawn is not implemented in Phase B")]
    PhaseBNotImplemented,
    #[error("creation-time Job assignment is unsupported")]
    CreationTimeAssignmentUnsupported,
    #[error("Win32 {operation:?} failed with code {code}")]
    Win32 {
        operation: Win32Operation,
        code: u32,
    },
    #[error("KILL_ON_JOB_CLOSE readback did not report the limit")]
    KillOnCloseNotSet,
    #[error("root identity could not be observed while suspended")]
    IdentityUnavailable,
    #[error("resume failed with code {code}")]
    ResumeFailed { code: u32 },
    #[error("stdio handle already taken")]
    StdioAlreadyTaken,
    #[error("owned process handle is closed")]
    Closed,
    #[error("root wait failed")]
    WaitFailed,
    #[error("Job enumeration failed: {reason:?}")]
    EnumerationFailed { reason: EnumerationLimit },
    #[error("termination proof unavailable: {reason:?}")]
    ProofUnavailable { reason: ProofUnavailableReason },
    #[error("termination deadline exceeded")]
    Timeout,
    #[error("process state is unknown; recovery is required")]
    RecoveryRequired { reason: RecoveryReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Win32Operation {
    CreateJob,
    SetJobInformation,
    QueryJobInformation,
    CreateProcess,
    UpdateProcThreadAttribute,
    ResumeThread,
    TerminateJob,
    QueryJobProcessIdList,
    QueryJobAccounting,
    WaitForSingleObject,
}

// ---------------------------------------------------------------------------
// Platform capabilities (D3) — design targets, never live PASS claims
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformCapabilities {
    pub owned_spawn: bool,
    pub creation_time_job: bool,
    pub job_enumeration: bool,
    pub hard_crash_cleanup: bool,
}

/// Windows capabilities. `hard_crash_cleanup` is a design target qualified by
/// the S0 smoke probe only (D32; A-D3-2) — not a live PASS.
pub const WINDOWS_CAPABILITIES: PlatformCapabilities = PlatformCapabilities {
    owned_spawn: true,
    creation_time_job: true,
    job_enumeration: true,
    hard_crash_cleanup: true,
};

pub const POSIX_CAPABILITIES: PlatformCapabilities = PlatformCapabilities {
    owned_spawn: false,
    creation_time_job: false,
    job_enumeration: false,
    hard_crash_cleanup: false,
};

// ---------------------------------------------------------------------------
// Termination proof persistence (PM decision D5, no new table)
// ---------------------------------------------------------------------------

/// Exactly one of `proof` and `unavailable` is present. Persisted as one
/// `evidence` row + `owned_processes` state + audit row in one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationProofEvidence {
    pub evidence_id: super::primitives::EvidenceId,
    pub dispatch_id: super::primitives::DispatchId,
    pub attempt_id: super::primitives::AttemptId,
    /// Exactly one of `proof` and `unavailable` is present.
    pub proof: Option<TerminationProof>,
    pub unavailable: Option<ProofUnavailableReason>,
    pub limitations: Vec<ProofLimitation>,
    pub redaction_version: super::primitives::RedactionVersion,
}

impl TerminationProofEvidence {
    pub fn is_complete(&self) -> bool {
        self.proof
            .as_ref()
            .map(TerminationProof::is_complete)
            .unwrap_or(false)
    }

    pub fn validate(&self) -> Result<(), ProcessError> {
        if self.proof.is_some() == self.unavailable.is_some() {
            return Err(ProcessError::WaitFailed);
        }
        Ok(())
    }

    /// Domain-separated digest of the canonical proof JSON; the caller supplies
    /// bytes produced by the C5 canonical encoder.
    pub fn proof_digest(&self, canonical_json: &[u8]) -> super::primitives::Sha256Digest {
        super::audit::domain_digest(b"vestry.termination.proof.v1", canonical_json).into()
    }
}
