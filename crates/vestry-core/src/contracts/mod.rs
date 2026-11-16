//! C1–C8 frozen contract types (Phase B S1).
//!
//! Design sources: LLD §1, §3, §8, §9; HLD §2/§5; T41 §3. Track code imports
//! these types; tracks must not add contracts outside this module.

pub mod adapter;
pub mod audit;
pub mod certificate;
pub mod channel;
pub mod dispatch;
pub mod doctor;
pub mod pin;
pub mod platform;
pub mod primitives;
pub mod process;
pub mod schema;
pub mod state;
pub mod status;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use primitives::{
    AdmissionId, AnchorId, ApprovalId, AttemptId, AuditSequence, BoxFuture, BranchName, CanaryId,
    CertificateId, CheckIntentRef, CheckManifestId, CheckResultId, ClarificationId, ConditionId,
    CreationFiletime, CriterionId, DaemonGeneration, DispatchId, DispatchOrdinal, EffectId,
    EnvironmentFingerprint, EvidenceId, EvidenceRevision, Fence, FingerprintDigest, GateArtefactId,
    GateDecisionId, GitSha, GoalId, Hash32, IdempotencyKey, JobGeneration, LeaseId, ManifestId,
    MemoryFactId, MessageId, OutboxId, OutboxKey, PartId, PinRevision, PolicyRevision,
    ProcessRecordId, ProjectId, RecoveryFindingId, RedactionVersion, ReviewId, ReviewIntentRef,
    Revision, RouteFingerprint, RunId, SafeCode, SafeId, SafeRelativePath, SafeText, ScratchScope,
    SessionId, Sha256Digest, SnapshotRef, StateRequestId, TaskId, TextError, TrelloBoardId,
    TrelloCardId, TrelloCommentId, TrelloListId, UtcMillis, WindowsAbsolutePath,
};
