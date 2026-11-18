//! Track 1 B1.1 acceptance: migration train, single-writer commits, atomic
//! state+audit+outbox, C5 audit persistence, typed queries (model-free).

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tempfile::TempDir;
use vestry_core::contracts::adapter::{InboxKey, InboxSource, Role};
use vestry_core::contracts::audit::{
    canonical_bytes, AnchoredInvocationScope, AuditAction, AuditActor, AuditEventDraft,
    AuditGateRef, AuditOperation, AuditOutcome, AuditReason, AuditScope, ChainVerdict, PolicyRef,
    PreAnchorDiscoveryScope, StateCode,
};
use vestry_core::contracts::certificate::{CertificateAbsentReason, CertificateVerdict};
use vestry_core::contracts::primitives::{
    AdmissionId, AnchorId, AttemptId, CanaryId, CertificateId, CreationFiletime, CriterionId,
    DaemonGeneration, DispatchId, DispatchOrdinal, EvidenceId, Fence, FingerprintDigest, GitSha,
    GoalId, JobGeneration, LeaseId, ManifestId, OutboxId, OutboxKey, PolicyRevision,
    ProcessRecordId, Revision, SafeCode, SafeRelativePath, ScratchScope, Sha256Digest, TaskId,
    UtcMillis,
};
use vestry_core::contracts::process::{
    ProcessIdentity, ProofUnavailableReason, TerminationProofEvidence,
};
use vestry_core::contracts::schema::{MigrationId, SchemaVersion, TABLE_NAMES};
use vestry_core::contracts::state::{
    request_id, ObjectRevision, OutboxDestination, OutboxIntent, OutboxState, OutboxView,
    StateError, StateMutation, StateOp, StateQuery, StateReply, StateTarget, StateTxn,
};
use vestry_core::contracts::status::{
    AttemptState, DispatchIntentState, EvidenceIntegrity, EvidenceRecord, EvidenceType,
    ProcessObservedState,
};
use vestry_core::state::SqliteStateStore;

const HASH_A: &str = "b72c9a1f741f80265d60778b00eb68c379e138a60a0860cfdbf901bfa9d73822";
const HASH_B: &str = "02672c6da7fd439af645df5f73d3252a97f3a49c2088681c60882ced01ad1650";
const HASH_C: &str = "a664aff0410c0fb1dba9b25ec0f33add0ea5400ab70c4a56f9365666a26aa3ec";

fn actor() -> AuditActor {
    AuditActor::Supervisor {
        generation: DaemonGeneration(7),
    }
}

fn policy() -> Vec<PolicyRef> {
    vec![PolicyRef::revision(PolicyRevision(7))]
}

fn denial(reason: &str) -> AuditAction {
    AuditAction::Denial {
        operation: AuditOperation(SafeCode::new("discovery_preflight").expect("operation")),
        reason: AuditReason(SafeCode::new(reason).expect("reason")),
    }
}

fn discovery_scope(
    admission: &str,
    attempt: &str,
    ordinal: u32,
    fence: u64,
    scratch: &str,
) -> AuditScope {
    AuditScope::PreAnchorDiscovery(PreAnchorDiscoveryScope {
        goal_id: GoalId::new("goal_01").expect("goal"),
        intake_digest: Sha256Digest::from_hex(&"1".repeat(64)).expect("digest"),
        intake_revision: Revision(2),
        target_digest: Sha256Digest::from_hex(&"2".repeat(64)).expect("digest"),
        scratch_scope: ScratchScope::new(scratch).expect("scratch"),
        role: Role::Discovery,
        admission_id: AdmissionId::new(admission).expect("admission"),
        attempt_id: AttemptId::new(attempt).expect("attempt"),
        dispatch_ordinal: DispatchOrdinal(ordinal),
        fence: Fence(fence),
    })
}

fn draft(
    action: AuditAction,
    scope: AuditScope,
    evidence_refs: Vec<EvidenceId>,
    outcome: AuditOutcome,
    recorded_at_ms: i64,
) -> AuditEventDraft {
    AuditEventDraft {
        schema_version: 1,
        actor: actor(),
        action,
        scope,
        policy_refs: policy(),
        evidence_refs,
        outcome,
        recorded_at_ms: UtcMillis(recorded_at_ms),
    }
}

fn draft_a() -> AuditEventDraft {
    draft(
        denial("canary_unverified"),
        discovery_scope("adm_01", "att_01", 1, 9, "scratch/goal_01"),
        Vec::new(),
        AuditOutcome::Denied,
        1_763_100_000_000,
    )
}

fn draft_b() -> AuditEventDraft {
    draft(
        AuditAction::StateTransition {
            from: StateCode::Running,
            to: StateCode::CancelPending,
        },
        AuditScope::AnchoredInvocation(AnchoredInvocationScope {
            goal_id: GoalId::new("goal_01").expect("goal"),
            anchor_id: AnchorId::new("anc_01").expect("anchor"),
            criterion_ids: vec![
                CriterionId::new("crit_01").expect("criterion"),
                CriterionId::new("crit_02").expect("criterion"),
            ],
            admission_id: AdmissionId::new("adm_01").expect("admission"),
            attempt_id: AttemptId::new("att_01").expect("attempt"),
            dispatch_ordinal: DispatchOrdinal(1),
            fence: Fence(9),
            role: Role::Worker,
            base_sha: GitSha::from_hex(&"ab".repeat(20)).expect("sha"),
            certificate_ref: Some(CertificateId::new("cert_01").expect("cert")),
            gate_refs: vec![
                AuditGateRef(SafeCode::new("gate:1:rev7").expect("gate")),
                AuditGateRef(SafeCode::new("gate:2:rev7").expect("gate")),
                AuditGateRef(SafeCode::new("gate:3:plan1").expect("gate")),
            ],
            task_id: Some(TaskId::new("task_01").expect("task")),
            task_revision: Some(Revision(3)),
            lease_id: Some(LeaseId::new("lease_01").expect("lease")),
            dispatch_id: Some(DispatchId::new("dsp_01").expect("dispatch")),
        }),
        vec![EvidenceId::new("ev_01").expect("evidence")],
        AuditOutcome::Succeeded,
        1_763_100_000_123,
    )
}

fn draft_c() -> AuditEventDraft {
    draft(
        denial("malformed_policy"),
        discovery_scope(
            "adm_02",
            "att_02",
            2,
            10,
            r#"C:\Users\测试\vestry "quoted" path"#,
        ),
        Vec::new(),
        AuditOutcome::Denied,
        1_763_100_000_456,
    )
}

fn temp_store() -> (TempDir, PathBuf, SqliteStateStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.db");
    let store = SqliteStateStore::open(&path).expect("open store");
    (dir, path, store)
}

fn read_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("second connection");
    connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")
        .expect("configure");
    connection
}

fn build_txn(
    name: &str,
    generation: u64,
    mutations: Vec<StateMutation>,
    audit: Vec<AuditEventDraft>,
    outbox: Vec<OutboxIntent>,
) -> StateTxn {
    StateTxn::new(
        request_id(name).expect("request id"),
        DaemonGeneration(generation),
        UtcMillis(1_763_100_000_000),
        mutations,
        audit,
        outbox,
    )
    .expect("valid txn")
}

fn begin_generation(started_at_ms: i64) -> StateMutation {
    StateMutation {
        target: StateTarget::DaemonGeneration,
        expected_revision: None,
        op: StateOp::BeginDaemonGeneration {
            started_at_ms: UtcMillis(started_at_ms),
        },
    }
}

fn outbox_intent(id: &str, key: &str) -> OutboxIntent {
    OutboxIntent {
        outbox_id: OutboxId::new(id).expect("outbox id"),
        destination: OutboxDestination::Trello,
        key: OutboxKey::new(key).expect("outbox key"),
        aggregate_sequence: 1,
        payload_digest: Sha256Digest::digest(b"payload"),
        state: OutboxState::Pending,
    }
}

// ---------------------------------------------------------------------------
// 1. Migration train
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_train_creates_exactly_the_43_designed_tables() {
    let (_dir, path, store) = temp_store();

    let connection = read_connection(&path);
    let mut names: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("collect");
    names.sort();
    let mut expected: Vec<String> = TABLE_NAMES.iter().map(|name| name.to_string()).collect();
    expected.sort();
    assert_eq!(names, expected, "schema must be exactly C7's table set");

    let version: i64 = connection
        .query_row(
            "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("schema_migrations row");
    assert_eq!(version, 1);
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert_eq!(journal, "wal", "the writer must run in WAL mode");
    drop(connection);

    store.close().expect("close");
}

#[tokio::test]
async fn migration_checksum_mismatch_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.db");
    SqliteStateStore::open(&path)
        .expect("open")
        .close()
        .expect("close");

    let connection = Connection::open(&path).expect("connection");
    connection
        .execute(
            "UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1",
            [],
        )
        .expect("tamper");
    drop(connection);

    let error = SqliteStateStore::open(&path)
        .err()
        .expect("checksum must be checked");
    assert!(matches!(
        error,
        StateError::MigrationChecksumMismatch {
            migration: MigrationId(1)
        }
    ));
}

#[tokio::test]
async fn newer_schema_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.db");
    SqliteStateStore::open(&path)
        .expect("open")
        .close()
        .expect("close");

    let connection = Connection::open(&path).expect("connection");
    connection
        .execute(
            "INSERT INTO schema_migrations (version, checksum, applied_at_ms, binary_revision)
             VALUES (2, 'future', 0, 'future-binary')",
            [],
        )
        .expect("insert future migration");
    drop(connection);

    let error = SqliteStateStore::open(&path)
        .err()
        .expect("newer schema must fail closed");
    assert!(matches!(
        error,
        StateError::SchemaNewer {
            found: SchemaVersion(2),
            supported: SchemaVersion(1)
        }
    ));
}

// ---------------------------------------------------------------------------
// 2. Atomic all-or-nothing commit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failed_mutation_rolls_back_state_audit_and_outbox() {
    let (_dir, _path, store) = temp_store();

    let audit = draft_a();
    let intent = outbox_intent("outbox_rollback", "card:1");
    let txn = build_txn(
        "rollback",
        1,
        vec![
            begin_generation(1_763_100_000_000),
            StateMutation {
                target: StateTarget::Attempt(AttemptId::new("att_missing").expect("attempt")),
                expected_revision: None,
                op: StateOp::TransitionAttempt {
                    from: AttemptState::Reserved,
                    to: AttemptState::Running,
                },
            },
        ],
        vec![audit],
        vec![intent],
    );

    let error = store.submit(txn).await.expect_err("missing attempt fails");
    assert!(matches!(error, StateError::NotFound { .. }));

    assert!(
        matches!(
            store.query(StateQuery::CurrentOwnership).await,
            Err(StateError::NotFound { .. })
        ),
        "daemon generation insert must roll back"
    );
    let (events, verdict) = store.audit_chain().await.expect("audit chain");
    assert!(events.is_empty(), "audit append must roll back");
    assert!(matches!(verdict, ChainVerdict::Empty));
    assert!(matches!(
        store
            .query(StateQuery::OutboxView {
                outbox_id: OutboxId::new("outbox_rollback").expect("id"),
            })
            .await,
        Err(StateError::NotFound { .. })
    ));
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// 3. Generation, revisions and receipts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn receipt_carries_request_generation_audit_and_revisions() {
    let (_dir, _path, store) = temp_store();
    let audit = draft_a();

    let receipt = store
        .submit(build_txn(
            "begin",
            1,
            vec![begin_generation(1_763_100_000_000)],
            vec![audit],
            vec![outbox_intent("outbox_1", "card:22")],
        ))
        .await
        .expect("commit");

    assert_eq!(receipt.request_id, request_id("begin").expect("id"));
    assert_eq!(receipt.generation, DaemonGeneration(1));
    assert!(
        receipt.committed_at_ms.0 >= 1_763_100_000_000,
        "the commit timestamp is taken when the transaction commits"
    );
    assert_eq!(
        receipt.audit_sequence,
        Some(vestry_core::contracts::primitives::AuditSequence(1))
    );
    assert_eq!(receipt.audit_head.hash.to_hex(), HASH_A);
    assert_eq!(
        receipt.revisions,
        vec![ObjectRevision {
            target: StateTarget::DaemonGeneration,
            revision: Revision::INITIAL,
        }]
    );

    let reply = store
        .query(StateQuery::AuditHead)
        .await
        .expect("head query");
    let StateReply::AuditHead(head) = reply else {
        panic!("expected audit head");
    };
    assert_eq!(head.hash.to_hex(), HASH_A);
    store.close().expect("close");
}

#[tokio::test]
async fn non_current_generation_is_rejected_without_writing() {
    let (_dir, _path, store) = temp_store();
    store
        .submit(build_txn(
            "begin",
            1,
            vec![begin_generation(1_763_100_000_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("begin");

    let error = store
        .submit(build_txn(
            "stale",
            2,
            vec![StateMutation {
                target: StateTarget::DaemonGeneration,
                expected_revision: None,
                op: StateOp::MarkCleanShutdown {
                    at: UtcMillis(1_763_100_000_100),
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect_err("stale generation rejected");
    assert!(matches!(
        error,
        StateError::NotCurrentGeneration {
            expected: DaemonGeneration(1),
            found: DaemonGeneration(2)
        }
    ));

    let StateReply::CurrentOwnership(ownership) = store
        .query(StateQuery::CurrentOwnership)
        .await
        .expect("ownership")
    else {
        panic!("expected ownership");
    };
    assert_eq!(ownership.generation, DaemonGeneration(1));
    assert_eq!(ownership.previous_generation, None);
    store.close().expect("close");
}

#[tokio::test]
async fn optimistic_revision_conflict_is_typed() {
    let (_dir, _path, store) = temp_store();
    store
        .submit(build_txn(
            "begin",
            1,
            vec![begin_generation(1_763_100_000_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("begin");
    store
        .submit(build_txn(
            "launch",
            1,
            vec![StateMutation {
                target: StateTarget::Dispatch(DispatchId::new("dsp_1").expect("dispatch")),
                expected_revision: None,
                op: StateOp::RecordLaunchIntent {
                    dispatch_id: DispatchId::new("dsp_1").expect("dispatch"),
                    attempt_id: AttemptId::new("att_1").expect("attempt"),
                    admission_id: AdmissionId::new("adm_1").expect("admission"),
                    manifest_id: ManifestId::new("manifest_1").expect("manifest"),
                    canary_id: CanaryId::new("canary_1").expect("canary"),
                    lease_id: None,
                    fence: Fence::INITIAL,
                    intent_state: DispatchIntentState::Recorded,
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("launch");
    let record = ProcessRecordId::new("proc_1").expect("process");
    let created = store
        .submit(build_txn(
            "identity",
            1,
            vec![StateMutation {
                target: StateTarget::OwnedProcess(record.clone()),
                expected_revision: None,
                op: StateOp::RecordProcessIdentity {
                    dispatch_id: DispatchId::new("dsp_1").expect("dispatch"),
                    identity: ProcessIdentity {
                        pid: 4242,
                        creation_filetime: CreationFiletime(99),
                    },
                    executable_digest: Sha256Digest::digest(b"exe"),
                    job_generation: JobGeneration(1),
                    observed_state: ProcessObservedState::Running,
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("identity");
    assert_eq!(created.revisions[0].revision, Revision::INITIAL);

    store
        .submit(build_txn(
            "update",
            1,
            vec![StateMutation {
                target: StateTarget::OwnedProcess(record.clone()),
                expected_revision: Some(Revision::INITIAL),
                op: StateOp::UpdateOwnedProcessState {
                    observed_state: ProcessObservedState::Exited,
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("first update wins");

    let error = store
        .submit(build_txn(
            "stale-update",
            1,
            vec![StateMutation {
                target: StateTarget::OwnedProcess(record.clone()),
                expected_revision: Some(Revision::INITIAL),
                op: StateOp::UpdateOwnedProcessState {
                    observed_state: ProcessObservedState::Running,
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect_err("stale revision conflicts");
    assert!(matches!(
        error,
        StateError::Conflict {
            target: StateTarget::OwnedProcess(_),
            expected: Revision(0),
            actual: Revision(1)
        }
    ));

    let StateReply::DispatchView(view) = store
        .query(StateQuery::DispatchView {
            dispatch_id: DispatchId::new("dsp_1").expect("dispatch"),
        })
        .await
        .expect("dispatch view")
    else {
        panic!("expected dispatch view");
    };
    assert_eq!(
        view.record.state,
        vestry_core::contracts::status::DispatchState::LaunchIntent
    );
    assert_eq!(view.intent, Some(DispatchIntentState::Recorded));
    assert_eq!(view.session, None);

    let StateReply::AttemptView(attempt) = store
        .query(StateQuery::AttemptView {
            attempt_id: AttemptId::new("att_1").expect("attempt"),
        })
        .await
        .expect("attempt view")
    else {
        panic!("expected attempt view");
    };
    assert_eq!(attempt.record.state, AttemptState::LaunchIntent);
    assert_eq!(attempt.active_dispatch, None);
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// 4. Audit persistence through the frozen C5 encoder
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audit_rows_are_byte_exact_and_verify() {
    let (_dir, path, store) = temp_store();
    let a = draft_a();
    let b = draft_b();
    let c = draft_c();

    let first = store
        .submit(build_txn(
            "a",
            1,
            vec![begin_generation(1_763_100_000_000)],
            vec![a],
            Vec::new(),
        ))
        .await
        .expect("event a");
    assert_eq!(first.audit_head.hash.to_hex(), HASH_A);
    let second = store
        .submit(build_txn("b", 1, Vec::new(), vec![b], Vec::new()))
        .await
        .expect("event b");
    assert_eq!(second.audit_head.hash.to_hex(), HASH_B);
    let third = store
        .submit(build_txn("c", 1, Vec::new(), vec![c], Vec::new()))
        .await
        .expect("event c");
    assert_eq!(third.audit_head.hash.to_hex(), HASH_C);

    let (events, verdict) = store.audit_chain().await.expect("chain");
    assert_eq!(events.len(), 3);
    for (event, expected_len) in events.iter().zip([746usize, 789, 772]) {
        assert_eq!(
            canonical_bytes(event).expect("canonical").len(),
            expected_len,
            "canonical byte length must match the frozen vectors"
        );
    }
    assert!(matches!(
        verdict,
        ChainVerdict::Valid { head } if head.hash.to_hex() == HASH_C
    ));

    let connection = read_connection(&path);
    connection
        .execute(
            "UPDATE audit_events SET draft_json = replace(draft_json, 'malformed_policy', 'tampered_policy')
             WHERE sequence = 3",
            [],
        )
        .expect("tamper");
    drop(connection);

    let (_events, verdict) = store.audit_chain().await.expect("chain after tamper");
    assert!(matches!(
        verdict,
        ChainVerdict::EventHashMismatch {
            at_sequence: vestry_core::contracts::primitives::AuditSequence(3),
            ..
        }
    ));
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// 5. RecoveryView and other typed queries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_view_is_a_consistent_snapshot_including_adapter_sessions() {
    let (_dir, path, store) = temp_store();
    store
        .submit(build_txn(
            "begin",
            1,
            vec![begin_generation(1_763_100_000_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("begin");
    store
        .submit(build_txn(
            "launch",
            1,
            vec![StateMutation {
                target: StateTarget::Dispatch(DispatchId::new("dsp_1").expect("dispatch")),
                expected_revision: None,
                op: StateOp::RecordLaunchIntent {
                    dispatch_id: DispatchId::new("dsp_1").expect("dispatch"),
                    attempt_id: AttemptId::new("att_1").expect("attempt"),
                    admission_id: AdmissionId::new("adm_1").expect("admission"),
                    manifest_id: ManifestId::new("manifest_1").expect("manifest"),
                    canary_id: CanaryId::new("canary_1").expect("canary"),
                    lease_id: None,
                    fence: Fence::INITIAL,
                    intent_state: DispatchIntentState::Recorded,
                },
            }],
            Vec::new(),
            vec![outbox_intent("outbox_view", "card:22")],
        ))
        .await
        .expect("launch");

    let connection = read_connection(&path);
    connection
        .execute(
            "INSERT INTO leases (lease_id, attempt_id, kind, scope_json, generation, fence, state, revision)
             VALUES ('lease_1', 'att_1', '\"scratch\"', ?1, 1, 1, '\"active\"', 0)",
            [r#"{"kind":"scratch_directory","path":"C:\\work\\scratch"}"#],
        )
        .expect("lease fixture");
    connection
        .execute(
            "INSERT INTO adapter_stores (store_id, attempt_id, absolute_identity, session_id, export_state, updated_at_ms)
             VALUES ('store_1', 'att_1', 'C:\\work\\adapter', 'sess_1', '\"not_exported\"', 0)",
            [],
        )
        .expect("adapter fixture");
    drop(connection);

    let StateReply::RecoveryView(view) = store
        .query(StateQuery::RecoveryView {
            generation: DaemonGeneration(1),
        })
        .await
        .expect("recovery view")
    else {
        panic!("expected recovery view");
    };
    assert_eq!(view.generation, DaemonGeneration(1));
    assert_eq!(
        view.daemon.state,
        vestry_core::contracts::status::DaemonGenerationState::Starting
    );
    assert_eq!(view.launch_intents.len(), 1);
    assert_eq!(view.launch_intents[0].dispatch_id.as_str(), "dsp_1");
    assert_eq!(view.attempts.len(), 1);
    assert_eq!(view.dispatches.len(), 1);
    assert_eq!(view.leases.len(), 1);
    assert_eq!(
        view.leases[0].kind,
        vestry_core::contracts::state::LeaseKind::Scratch
    );
    assert_eq!(
        view.leases[0].state,
        vestry_core::contracts::state::LeaseState::Active
    );
    assert_eq!(
        view.adapter_sessions.len(),
        1,
        "P1-4 requires adapter sessions"
    );
    assert_eq!(view.adapter_sessions[0].store_id.as_str(), "store_1");
    assert_eq!(
        view.adapter_sessions[0]
            .session_id
            .as_ref()
            .map(|id| id.as_str()),
        Some("sess_1")
    );
    assert_eq!(view.pending_outbox.len(), 1);
    assert_eq!(view.pending_outbox[0].outbox_id.as_str(), "outbox_view");
    assert_eq!(view.audit_head.sequence.get(), 0);

    let StateReply::OutboxView(OutboxView { intent, .. }) = store
        .query(StateQuery::OutboxView {
            outbox_id: OutboxId::new("outbox_view").expect("id"),
        })
        .await
        .expect("outbox view")
    else {
        panic!("expected outbox view");
    };
    assert_eq!(intent.key.as_str(), "card:22");

    let StateReply::ReadinessCertificate(verdict) = store
        .query(StateQuery::ReadinessCertificate {
            certificate_id: CertificateId::new("cert_1").expect("cert"),
            input_fingerprint: FingerprintDigest(Sha256Digest::digest(b"fingerprint")),
        })
        .await
        .expect("certificate verdict")
    else {
        panic!("expected certificate verdict");
    };
    assert!(matches!(
        verdict,
        CertificateVerdict::Absent {
            reason: CertificateAbsentReason::NotIssued
        }
    ));
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// 6. Evidence, inbox and termination proof persistence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn evidence_inbox_and_termination_proof_are_persisted() {
    let (_dir, path, store) = temp_store();
    store
        .submit(build_txn(
            "begin",
            1,
            vec![begin_generation(1_763_100_000_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("begin");
    store
        .submit(build_txn(
            "launch",
            1,
            vec![StateMutation {
                target: StateTarget::Dispatch(DispatchId::new("dsp_t").expect("dispatch")),
                expected_revision: None,
                op: StateOp::RecordLaunchIntent {
                    dispatch_id: DispatchId::new("dsp_t").expect("dispatch"),
                    attempt_id: AttemptId::new("att_t").expect("attempt"),
                    admission_id: AdmissionId::new("adm_t").expect("admission"),
                    manifest_id: ManifestId::new("manifest_t").expect("manifest"),
                    canary_id: CanaryId::new("canary_t").expect("canary"),
                    lease_id: None,
                    fence: Fence::INITIAL,
                    intent_state: DispatchIntentState::Recorded,
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("launch");

    let evidence = EvidenceRecord {
        evidence_id: EvidenceId::new("ev_1").expect("evidence"),
        artefact: vestry_core::contracts::status::SafeArtifactRef {
            relative_path: SafeRelativePath::new("runs/att_t/proof.json").expect("path"),
            digest: Sha256Digest::digest(b"proof"),
            bytes: 42,
        },
        evidence_type: EvidenceType::TerminationProof,
        producer: actor(),
        revision: Revision(3),
        redaction_version: vestry_core::contracts::primitives::RedactionVersion(1),
        integrity: EvidenceIntegrity::Verified,
        created_at_ms: UtcMillis(1_763_100_000_000),
    };
    let record = ProcessRecordId::new("proc_t").expect("process");
    let receipt = store
        .submit(build_txn(
            "evidence",
            1,
            vec![
                StateMutation {
                    target: StateTarget::Evidence(EvidenceId::new("ev_1").expect("id")),
                    expected_revision: None,
                    op: StateOp::InsertEvidence {
                        evidence: evidence.clone(),
                    },
                },
                StateMutation {
                    target: StateTarget::OwnedProcess(record.clone()),
                    expected_revision: None,
                    op: StateOp::RecordProcessIdentity {
                        dispatch_id: DispatchId::new("dsp_t").expect("dispatch"),
                        identity: ProcessIdentity {
                            pid: 7,
                            creation_filetime: CreationFiletime(1),
                        },
                        executable_digest: Sha256Digest::digest(b"exe"),
                        job_generation: JobGeneration(1),
                        observed_state: ProcessObservedState::Running,
                    },
                },
            ],
            vec![draft_b()],
            Vec::new(),
        ))
        .await
        .expect("evidence commit");
    assert_eq!(receipt.revisions.len(), 2);

    store
        .submit(build_txn(
            "proof",
            1,
            vec![StateMutation {
                target: StateTarget::OwnedProcess(record),
                expected_revision: None,
                op: StateOp::RecordTerminationProof {
                    proof: TerminationProofEvidence {
                        evidence_id: evidence.evidence_id.clone(),
                        dispatch_id: DispatchId::new("dsp_t").expect("dispatch"),
                        attempt_id: AttemptId::new("att_t").expect("attempt"),
                        proof: None,
                        unavailable: Some(ProofUnavailableReason::PostRestart),
                        limitations: Vec::new(),
                        redaction_version: vestry_core::contracts::primitives::RedactionVersion(1),
                    },
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("proof commit");

    let StateReply::RecoveryView(view) = store
        .query(StateQuery::RecoveryView {
            generation: DaemonGeneration(1),
        })
        .await
        .expect("view")
    else {
        panic!("expected recovery view");
    };
    assert_eq!(
        view.owned_processes[0].observed_state,
        ProcessObservedState::RecoveryRequired
    );

    let connection = read_connection(&path);
    let stored: String = connection
        .query_row(
            "SELECT artefact FROM evidence WHERE evidence_id = 'ev_1'",
            [],
            |row| row.get(0),
        )
        .expect("evidence row");
    assert!(stored.contains("runs/att_t/proof.json"));
    assert!(stored.contains("sha256:"));
    drop(connection);

    let inbox = store
        .submit(build_txn(
            "inbox",
            1,
            vec![StateMutation {
                target: StateTarget::Session(
                    vestry_core::contracts::primitives::SessionId::new("sess_1").expect("session"),
                ),
                expected_revision: None,
                op: StateOp::RecordInbox {
                    source: InboxSource::Trello,
                    key: InboxKey(SafeCode::new("card:22:comment:1").expect("key")),
                    digest: Sha256Digest::digest(b"inbox"),
                    aggregate_sequence: 1,
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("inbox");
    assert_eq!(inbox.revisions[0].revision, Revision::INITIAL);

    let connection = read_connection(&path);
    let inbox_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM inbox", [], |row| row.get(0))
        .expect("inbox count");
    assert_eq!(inbox_rows, 1);
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// 7. Contract-level transaction guards at the boundary
// ---------------------------------------------------------------------------

#[test]
fn empty_duplicate_and_oversize_transactions_are_rejected() {
    let empty = StateTxn::new(
        request_id("empty").expect("id"),
        DaemonGeneration(1),
        UtcMillis(0),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert!(matches!(empty, Err(StateError::EmptyTransaction)));

    let audit = draft_a();
    let duplicate = StateTxn::new(
        request_id("dup").expect("id"),
        DaemonGeneration(1),
        UtcMillis(0),
        vec![begin_generation(0), begin_generation(0)],
        vec![audit.clone()],
        Vec::new(),
    );
    assert!(matches!(duplicate, Err(StateError::DuplicateTarget(_))));

    let mutations: Vec<StateMutation> = (0..1100)
        .map(|index| StateMutation {
            target: StateTarget::Attempt(AttemptId::new(format!("att_{index}")).expect("attempt")),
            expected_revision: None,
            op: StateOp::TransitionAttempt {
                from: AttemptState::Reserved,
                to: AttemptState::Running,
            },
        })
        .collect();
    let oversize = StateTxn::new(
        request_id("big").expect("id"),
        DaemonGeneration(1),
        UtcMillis(0),
        mutations,
        vec![audit],
        Vec::new(),
    );
    assert!(matches!(
        oversize,
        Err(StateError::TransactionTooLarge { limit: 1_048_576 })
    ));
}

// ---------------------------------------------------------------------------
// 8. Reader surface (SQLite off the executor)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_only_reader_serves_typed_queries_off_the_executor() {
    use vestry_core::contracts::state::StateReader;

    let (_dir, _path, store) = temp_store();
    store
        .submit(build_txn(
            "begin",
            1,
            vec![begin_generation(1_763_100_000_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("begin");

    let reader = store.open_reader().expect("reader");
    let StateReply::CurrentOwnership(ownership) = reader
        .read(StateQuery::CurrentOwnership)
        .await
        .expect("reader query")
    else {
        panic!("expected ownership");
    };
    assert_eq!(ownership.generation, DaemonGeneration(1));
    assert_eq!(ownership.previous_generation, None);
    store.close().expect("close");
}
