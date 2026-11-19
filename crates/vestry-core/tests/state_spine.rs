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
    ActionId, AdmissionId, AnchorId, AttemptId, BranchName, CanaryId, CertificateId,
    CreationFiletime, CriterionId, DaemonGeneration, DispatchId, DispatchOrdinal, EvidenceId,
    Fence, FingerprintDigest, GitSha, GoalId, JobGeneration, LeaseId, ManifestId, OutboxId,
    OutboxKey, PolicyRevision, ProcessRecordId, RedactionVersion, Revision, SafeCode,
    SafeRelativePath, ScratchScope, Sha256Digest, TaskId, UtcMillis, WindowsAbsolutePath,
};
use vestry_core::contracts::process::{
    EnumerationCompleteness, ObserverIdentity, ProcessEnumeration, ProcessIdentity,
    ProofUnavailableReason, TerminationProof, TerminationProofEvidence,
};
use vestry_core::contracts::schema::{InternalErrorCode, MigrationId, SchemaVersion, TABLE_NAMES};
use vestry_core::contracts::state::{
    request_id, LeaseKind, LeaseScope, LeaseState, ObjectRevision, OutboxDestination, OutboxIntent,
    OutboxState, OutboxView, StateError, StateMutation, StateOp, StateQuery, StateReply,
    StateTarget, StateTxn,
};
use vestry_core::contracts::status::{
    AttemptState, DispatchIntentState, DispatchState, EvidenceIntegrity, EvidenceRecord,
    EvidenceType, ProcessObservedState,
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

fn launch_mutation(dispatch: &str, attempt: &str) -> StateMutation {
    StateMutation {
        target: StateTarget::Dispatch(DispatchId::new(dispatch).expect("dispatch")),
        expected_revision: None,
        op: StateOp::RecordLaunchIntent {
            dispatch_id: DispatchId::new(dispatch).expect("dispatch"),
            attempt_id: AttemptId::new(attempt).expect("attempt"),
            admission_id: AdmissionId::new("adm_t").expect("admission"),
            manifest_id: ManifestId::new("manifest_t").expect("manifest"),
            canary_id: CanaryId::new("canary_t").expect("canary"),
            lease_id: None,
            fence: Fence::INITIAL,
            intent_state: DispatchIntentState::Recorded,
        },
    }
}

async fn begin_and_launch(
    store: &SqliteStateStore,
    dispatch: &str,
    attempt: &str,
) -> ProcessRecordId {
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
            vec![launch_mutation(dispatch, attempt)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("launch");
    let record = ProcessRecordId::new(format!("proc_{attempt}")).expect("record");
    store
        .submit(build_txn(
            "identity",
            1,
            vec![StateMutation {
                target: StateTarget::OwnedProcess(record.clone()),
                expected_revision: None,
                op: StateOp::RecordProcessIdentity {
                    dispatch_id: DispatchId::new(dispatch).expect("dispatch"),
                    identity: ProcessIdentity {
                        pid: 7,
                        creation_filetime: CreationFiletime(1),
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
    record
}

async fn owned_state(store: &SqliteStateStore) -> ProcessObservedState {
    let StateReply::RecoveryView(view) = store
        .query(StateQuery::RecoveryView {
            generation: DaemonGeneration(1),
        })
        .await
        .expect("view")
    else {
        panic!("expected recovery view");
    };
    view.owned_processes[0].observed_state
}

fn evidence_record(id: &str, integrity: EvidenceIntegrity) -> EvidenceRecord {
    EvidenceRecord {
        evidence_id: EvidenceId::new(id).expect("evidence"),
        artefact: vestry_core::contracts::status::SafeArtifactRef {
            relative_path: SafeRelativePath::new(format!("runs/{id}/proof.json")).expect("path"),
            digest: Sha256Digest::digest(id.as_bytes()),
            bytes: 42,
        },
        evidence_type: EvidenceType::TerminationProof,
        producer: actor(),
        revision: Revision(3),
        redaction_version: RedactionVersion(1),
        integrity,
        created_at_ms: UtcMillis(1_763_100_000_000),
    }
}

fn complete_proof(dispatch: &str) -> TerminationProof {
    TerminationProof {
        dispatch_id: DispatchId::new(dispatch).expect("dispatch"),
        job_generation: JobGeneration(1),
        root: ProcessIdentity {
            pid: 7,
            creation_filetime: CreationFiletime(1),
        },
        root_signalled: true,
        enumeration: ProcessEnumeration {
            observed_at_ms: UtcMillis(1_763_100_000_000),
            identities: Vec::new(),
            active_processes: 0,
            completeness: EnumerationCompleteness::Complete,
        },
        observer: ObserverIdentity::Supervisor {
            generation: DaemonGeneration(1),
        },
        observed_at_ms: UtcMillis(1_763_100_000_000),
        limitations: Vec::new(),
    }
}

fn proof_evidence(
    evidence_id: &str,
    dispatch: &str,
    attempt: &str,
    proof: Option<TerminationProof>,
    unavailable: Option<ProofUnavailableReason>,
) -> TerminationProofEvidence {
    TerminationProofEvidence {
        evidence_id: EvidenceId::new(evidence_id).expect("evidence"),
        dispatch_id: DispatchId::new(dispatch).expect("dispatch"),
        attempt_id: AttemptId::new(attempt).expect("attempt"),
        proof,
        unavailable,
        limitations: Vec::new(),
        redaction_version: RedactionVersion(1),
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
async fn schema_migrations_history_is_insert_only_and_checksum_tamper_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.db");
    SqliteStateStore::open(&path)
        .expect("open")
        .close()
        .expect("close");

    let connection = Connection::open(&path).expect("connection");
    let update = connection.execute(
        "UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1",
        [],
    );
    assert!(
        update.is_err(),
        "C7 §8.3.5: a bare UPDATE of schema_migrations must fail"
    );
    let delete = connection.execute("DELETE FROM schema_migrations WHERE version = 1", []);
    assert!(
        delete.is_err(),
        "C7 §8.3.5: a bare DELETE of schema_migrations must fail"
    );
    // Tamper on a scratch copy where the protective trigger has been removed;
    // startup must still catch it through the checksum comparison.
    connection
        .execute_batch(
            "DROP TRIGGER schema_migrations_no_update;
             UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1;",
        )
        .expect("tamper with the trigger dropped");
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
async fn missing_table_fails_startup_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.db");
    SqliteStateStore::open(&path)
        .expect("open")
        .close()
        .expect("close");

    let connection = Connection::open(&path).expect("connection");
    connection
        .execute_batch("DROP TABLE audit_events")
        .expect("drop table");
    drop(connection);

    let error = SqliteStateStore::open(&path)
        .err()
        .expect("an incomplete inventory must fail closed");
    assert!(matches!(
        error,
        StateError::Internal {
            code: InternalErrorCode::Invariant
        }
    ));
}

/// Hook `schema::fk_topological` (REQUIRE NOW): a dangling reference in an
/// otherwise checksum-valid database fails startup closed.
#[tokio::test]
async fn dangling_foreign_key_fails_startup_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.db");
    SqliteStateStore::open(&path)
        .expect("open")
        .close()
        .expect("close");

    let connection = Connection::open(&path).expect("connection");
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .expect("disable enforcement");
    connection
        .execute(
            "INSERT INTO dispatches
                 (dispatch_id, attempt_id, ordinal, binding_kind, state, created_at_ms, revision)
             VALUES ('dsp_orphan', 'att_orphan', 1, '\"anchored_invocation\"',
                     '\"launch_intent\"', 0, 0)",
            [],
        )
        .expect("dangling dispatch fixture");
    drop(connection);

    let error = SqliteStateStore::open(&path)
        .err()
        .expect("a dangling reference must fail closed");
    assert!(matches!(
        error,
        StateError::Internal {
            code: InternalErrorCode::Invariant
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
async fn generation_n_plus_one_begins_with_prior_shutdown_state() {
    // Clean prior shutdown: generation 2 records a clean previous generation.
    let (_dir, _path, store) = temp_store();
    store
        .submit(build_txn(
            "begin-1",
            1,
            vec![begin_generation(1_763_100_000_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("begin generation 1");
    let clean = store
        .submit(build_txn(
            "clean-1",
            1,
            vec![StateMutation {
                target: StateTarget::DaemonGeneration,
                expected_revision: Some(Revision::INITIAL),
                op: StateOp::MarkCleanShutdown {
                    at: UtcMillis(1_763_100_000_500),
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("clean shutdown of generation 1");
    assert_eq!(clean.revisions[0].revision, Revision(1));
    store
        .submit(build_txn(
            "begin-2",
            2,
            vec![begin_generation(1_763_100_001_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("generation 2 must begin after a clean shutdown");

    let StateReply::CurrentOwnership(ownership) = store
        .query(StateQuery::CurrentOwnership)
        .await
        .expect("ownership")
    else {
        panic!("expected ownership");
    };
    assert_eq!(ownership.generation, DaemonGeneration(2));
    assert_eq!(ownership.previous_generation, Some(DaemonGeneration(1)));
    assert_eq!(ownership.previous_clean_shutdown, Some(true));
    store.close().expect("close");

    // Unclean prior shutdown: the same restart path is reachable and the
    // carried state reports that the previous generation did not stop cleanly.
    let (_dir, _path, store) = temp_store();
    store
        .submit(build_txn(
            "begin-1",
            1,
            vec![begin_generation(1_763_100_000_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("begin generation 1");
    store
        .submit(build_txn(
            "begin-2",
            2,
            vec![begin_generation(1_763_100_001_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("generation 2 must begin after an unclean shutdown");

    let StateReply::CurrentOwnership(ownership) = store
        .query(StateQuery::CurrentOwnership)
        .await
        .expect("ownership")
    else {
        panic!("expected ownership");
    };
    assert_eq!(ownership.generation, DaemonGeneration(2));
    assert_eq!(ownership.previous_generation, Some(DaemonGeneration(1)));
    assert_eq!(ownership.previous_clean_shutdown, Some(false));
    store.close().expect("close");
}

#[tokio::test]
async fn skipped_or_duplicate_generation_begin_is_rejected() {
    let (_dir, _path, store) = temp_store();
    store
        .submit(build_txn(
            "begin-1",
            1,
            vec![begin_generation(1_763_100_000_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("begin generation 1");
    store
        .submit(build_txn(
            "begin-2",
            2,
            vec![begin_generation(1_763_100_001_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("begin generation 2");

    let skipped = store
        .submit(build_txn(
            "begin-4",
            4,
            vec![begin_generation(1_763_100_002_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect_err("a skipped generation must be rejected");
    assert!(matches!(
        skipped,
        StateError::NotCurrentGeneration {
            expected: DaemonGeneration(3),
            found: DaemonGeneration(4)
        }
    ));

    let duplicate = store
        .submit(build_txn(
            "begin-2-again",
            2,
            vec![begin_generation(1_763_100_002_000)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect_err("re-beginning the current generation must be rejected");
    assert!(matches!(
        duplicate,
        StateError::NotCurrentGeneration {
            expected: DaemonGeneration(3),
            found: DaemonGeneration(2)
        }
    ));
    store.close().expect("close");
}

#[tokio::test]
async fn daemon_generation_cas_reads_the_current_revision() {
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

    let first = store
        .submit(build_txn(
            "clean-1",
            1,
            vec![StateMutation {
                target: StateTarget::DaemonGeneration,
                expected_revision: Some(Revision::INITIAL),
                op: StateOp::MarkCleanShutdown {
                    at: UtcMillis(1_763_100_000_500),
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("first CAS wins");
    assert_eq!(first.revisions[0].revision, Revision(1));

    let stale = store
        .submit(build_txn(
            "clean-stale",
            1,
            vec![StateMutation {
                target: StateTarget::DaemonGeneration,
                expected_revision: Some(Revision::INITIAL),
                op: StateOp::MarkCleanShutdown {
                    at: UtcMillis(1_763_100_000_900),
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect_err("stale generation revision must conflict");
    assert!(matches!(
        stale,
        StateError::Conflict {
            target: StateTarget::DaemonGeneration,
            expected: Revision(0),
            actual: Revision(1)
        }
    ));

    let second = store
        .submit(build_txn(
            "clean-2",
            1,
            vec![StateMutation {
                target: StateTarget::DaemonGeneration,
                expected_revision: Some(Revision(1)),
                op: StateOp::MarkCleanShutdown {
                    at: UtcMillis(1_763_100_001_400),
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("current revision CAS succeeds");
    assert_eq!(second.revisions[0].revision, Revision(2));
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
    assert_eq!(view.record.state, DispatchState::LaunchIntent);
    assert_eq!(view.intent, Some(DispatchIntentState::Recorded));
    assert_eq!(view.session, None);
    assert_eq!(
        view.record.ordinal,
        DispatchOrdinal::FIRST,
        "T45 §5: the first dispatch of an attempt is ordinal 1"
    );

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
    assert_eq!(
        attempt.active_dispatch,
        Some(DispatchId::new("dsp_1").expect("dispatch"))
    );
    store.close().expect("close");
}

/// R5: an identity upsert must not retarget an existing dispatch binding to a
/// different process record id, nor regress its stored revision.
#[tokio::test]
async fn record_process_identity_cannot_retarget_a_bound_dispatch() {
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
            vec![launch_mutation("dsp_bound", "att_bound")],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("launch");

    let first = ProcessRecordId::new("proc_first").expect("record");
    store
        .submit(build_txn(
            "identity",
            1,
            vec![StateMutation {
                target: StateTarget::OwnedProcess(first.clone()),
                expected_revision: None,
                op: StateOp::RecordProcessIdentity {
                    dispatch_id: DispatchId::new("dsp_bound").expect("dispatch"),
                    identity: ProcessIdentity {
                        pid: 11,
                        creation_filetime: CreationFiletime(2),
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
        .expect("initial identity");

    let retarget = ProcessRecordId::new("proc_second").expect("record");
    let error = store
        .submit(build_txn(
            "retarget",
            1,
            vec![StateMutation {
                target: StateTarget::OwnedProcess(retarget),
                expected_revision: None,
                op: StateOp::RecordProcessIdentity {
                    dispatch_id: DispatchId::new("dsp_bound").expect("dispatch"),
                    identity: ProcessIdentity {
                        pid: 12,
                        creation_filetime: CreationFiletime(3),
                    },
                    executable_digest: Sha256Digest::digest(b"other"),
                    job_generation: JobGeneration(1),
                    observed_state: ProcessObservedState::Running,
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect_err("a different record id must not retarget the row");
    assert!(matches!(
        error,
        StateError::ConstraintViolation {
            constraint: "owned_processes_process_record_id"
        }
    ));

    let connection = read_connection(&path);
    let (record, revision, pid): (String, i64, Option<i64>) = connection
        .query_row(
            "SELECT process_record_id, revision, identity_pid FROM owned_processes",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("owned process row");
    assert_eq!(record, "proc_first");
    assert_eq!(revision, 0, "the stored revision must not regress");
    assert_eq!(pid, Some(11), "ownership must not be rewritten");
    drop(connection);
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
async fn evidence_persists_the_supplied_timestamp() {
    let (_dir, path, store) = temp_store();
    begin_and_launch(&store, "dsp_t", "att_t").await;

    let evidence = evidence_record("ev_1", EvidenceIntegrity::Verified);
    let receipt = store
        .submit(build_txn(
            "evidence",
            1,
            vec![StateMutation {
                target: StateTarget::Evidence(EvidenceId::new("ev_1").expect("id")),
                expected_revision: None,
                op: StateOp::InsertEvidence {
                    evidence: evidence.clone(),
                },
            }],
            vec![draft_b()],
            Vec::new(),
        ))
        .await
        .expect("evidence commit");
    assert_eq!(receipt.revisions.len(), 1);

    let connection = read_connection(&path);
    let stored: String = connection
        .query_row(
            "SELECT artefact FROM evidence WHERE evidence_id = 'ev_1'",
            [],
            |row| row.get(0),
        )
        .expect("evidence row");
    assert!(stored.contains("runs/ev_1/proof.json"));
    assert!(stored.contains("sha256:"));
    let created: i64 = connection
        .query_row(
            "SELECT created_at_ms FROM evidence WHERE evidence_id = 'ev_1'",
            [],
            |row| row.get(0),
        )
        .expect("created_at");
    assert_eq!(
        created, 1_763_100_000_000,
        "F7: the supplied evidence timestamp is persisted verbatim"
    );
    drop(connection);

    store.close().expect("close");
}

/// Hook `proof_persist::complete_evidence_audit_state` (REQUIRE NOW): a
/// complete proof commits the evidence row, the observed `Terminated` state,
/// the audit event and the lifecycle transition in one transaction.
#[tokio::test]
async fn termination_proof_complete_commits_evidence_state_audit_and_transition() {
    let (_dir, path, store) = temp_store();
    let record = begin_and_launch(&store, "dsp_p", "att_p").await;
    store
        .submit(build_txn(
            "cancel-pending",
            1,
            vec![StateMutation {
                target: StateTarget::Attempt(AttemptId::new("att_p").expect("attempt")),
                expected_revision: None,
                op: StateOp::TransitionAttempt {
                    from: AttemptState::LaunchIntent,
                    to: AttemptState::CancelPending,
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("cancel pending");

    let proof = proof_evidence(
        "ev_p",
        "dsp_p",
        "att_p",
        Some(complete_proof("dsp_p")),
        None,
    );
    let receipt = store
        .submit(build_txn(
            "proof",
            1,
            vec![
                StateMutation {
                    target: StateTarget::Evidence(EvidenceId::new("ev_p").expect("evidence")),
                    expected_revision: None,
                    op: StateOp::InsertEvidence {
                        evidence: evidence_record("ev_p", EvidenceIntegrity::Verified),
                    },
                },
                StateMutation {
                    target: StateTarget::OwnedProcess(record),
                    expected_revision: None,
                    op: StateOp::RecordTerminationProof { proof },
                },
                StateMutation {
                    target: StateTarget::Attempt(AttemptId::new("att_p").expect("attempt")),
                    expected_revision: Some(Revision(1)),
                    op: StateOp::TransitionAttempt {
                        from: AttemptState::CancelPending,
                        to: AttemptState::Cancelled,
                    },
                },
            ],
            vec![draft_a()],
            Vec::new(),
        ))
        .await
        .expect("a complete proof commits its authority chain");
    assert_eq!(receipt.revisions.len(), 3);
    assert!(receipt.audit_sequence.is_some());

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
        ProcessObservedState::Terminated
    );
    assert_eq!(view.attempts[0].state, AttemptState::Cancelled);
    assert_eq!(view.audit_head.sequence.get(), 1);

    let connection = read_connection(&path);
    let (created, integrity): (i64, String) = connection
        .query_row(
            "SELECT created_at_ms, integrity FROM evidence WHERE evidence_id = 'ev_p'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("evidence row");
    assert_eq!(created, 1_763_100_000_000);
    assert_eq!(integrity, "\"verified\"");
    drop(connection);
    store.close().expect("close");
}

#[tokio::test]
async fn termination_proof_unavailable_commits_recovery_with_unavailable_evidence() {
    let (_dir, _path, store) = temp_store();
    let record = begin_and_launch(&store, "dsp_u", "att_u").await;
    let proof = proof_evidence(
        "ev_u",
        "dsp_u",
        "att_u",
        None,
        Some(ProofUnavailableReason::PostRestart),
    );
    store
        .submit(build_txn(
            "proof",
            1,
            vec![
                StateMutation {
                    target: StateTarget::Evidence(EvidenceId::new("ev_u").expect("evidence")),
                    expected_revision: None,
                    op: StateOp::InsertEvidence {
                        evidence: evidence_record("ev_u", EvidenceIntegrity::Unavailable),
                    },
                },
                StateMutation {
                    target: StateTarget::OwnedProcess(record),
                    expected_revision: None,
                    op: StateOp::RecordTerminationProof { proof },
                },
            ],
            vec![draft_a()],
            Vec::new(),
        ))
        .await
        .expect("an unavailable proof still records its evidence and audit");
    assert_eq!(
        owned_state(&store).await,
        ProcessObservedState::RecoveryRequired
    );
    store.close().expect("close");

    // A proof that is not complete can never carry `Verified` evidence.
    let (_dir, _path, store) = temp_store();
    let record = begin_and_launch(&store, "dsp_v", "att_v").await;
    let proof = proof_evidence(
        "ev_v",
        "dsp_v",
        "att_v",
        None,
        Some(ProofUnavailableReason::PostRestart),
    );
    let error = store
        .submit(build_txn(
            "bad-integrity",
            1,
            vec![
                StateMutation {
                    target: StateTarget::Evidence(EvidenceId::new("ev_v").expect("evidence")),
                    expected_revision: None,
                    op: StateOp::InsertEvidence {
                        evidence: evidence_record("ev_v", EvidenceIntegrity::Verified),
                    },
                },
                StateMutation {
                    target: StateTarget::OwnedProcess(record),
                    expected_revision: None,
                    op: StateOp::RecordTerminationProof { proof },
                },
            ],
            vec![draft_a()],
            Vec::new(),
        ))
        .await
        .expect_err("unavailable proof must not claim verified evidence");
    assert!(matches!(
        error,
        StateError::ConstraintViolation {
            constraint: "termination_proof_integrity"
        }
    ));
    assert_eq!(owned_state(&store).await, ProcessObservedState::Running);
    store.close().expect("close");
}

#[tokio::test]
async fn termination_proof_without_companions_is_rejected_and_rolls_back() {
    let (_dir, path, store) = temp_store();
    let record = begin_and_launch(&store, "dsp_r", "att_r").await;
    let proof = proof_evidence(
        "ev_r",
        "dsp_r",
        "att_r",
        Some(complete_proof("dsp_r")),
        None,
    );

    // (a) A proof-only transaction has no evidence link.
    let proof_only = store
        .submit(build_txn(
            "proof-only",
            1,
            vec![StateMutation {
                target: StateTarget::OwnedProcess(record.clone()),
                expected_revision: None,
                op: StateOp::RecordTerminationProof {
                    proof: proof.clone(),
                },
            }],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect_err("a proof without evidence must be rejected");
    assert!(matches!(
        proof_only,
        StateError::ConstraintViolation {
            constraint: "termination_proof_evidence"
        }
    ));

    // (b) Evidence without an audit event is not authoritative.
    let no_audit = store
        .submit(build_txn(
            "no-audit",
            1,
            vec![
                StateMutation {
                    target: StateTarget::Evidence(EvidenceId::new("ev_r").expect("evidence")),
                    expected_revision: None,
                    op: StateOp::InsertEvidence {
                        evidence: evidence_record("ev_r", EvidenceIntegrity::Verified),
                    },
                },
                StateMutation {
                    target: StateTarget::OwnedProcess(record.clone()),
                    expected_revision: None,
                    op: StateOp::RecordTerminationProof {
                        proof: proof.clone(),
                    },
                },
            ],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect_err("a proof without an audit event must be rejected");
    assert!(matches!(
        no_audit,
        StateError::ConstraintViolation {
            constraint: "termination_proof_audit"
        }
    ));

    // (c) A proof naming another dispatch does not bind to this process.
    let wrong_dispatch = proof_evidence(
        "ev_r",
        "dsp_other",
        "att_r",
        Some(complete_proof("dsp_other")),
        None,
    );
    let unbound = store
        .submit(build_txn(
            "wrong-dispatch",
            1,
            vec![
                StateMutation {
                    target: StateTarget::Evidence(EvidenceId::new("ev_r").expect("evidence")),
                    expected_revision: None,
                    op: StateOp::InsertEvidence {
                        evidence: evidence_record("ev_r", EvidenceIntegrity::Verified),
                    },
                },
                StateMutation {
                    target: StateTarget::OwnedProcess(record.clone()),
                    expected_revision: None,
                    op: StateOp::RecordTerminationProof {
                        proof: wrong_dispatch,
                    },
                },
            ],
            vec![draft_a()],
            Vec::new(),
        ))
        .await
        .expect_err("a foreign dispatch binding must be rejected");
    assert!(matches!(
        unbound,
        StateError::ConstraintViolation {
            constraint: "termination_proof_dispatch"
        }
    ));

    // (d) Hook `proof_persist::commit_failure`: a late mutation failure rolls
    // back the evidence row, the observed state and the audit event.
    let late = store
        .submit(build_txn(
            "late-failure",
            1,
            vec![
                StateMutation {
                    target: StateTarget::Evidence(EvidenceId::new("ev_r").expect("evidence")),
                    expected_revision: None,
                    op: StateOp::InsertEvidence {
                        evidence: evidence_record("ev_r", EvidenceIntegrity::Verified),
                    },
                },
                StateMutation {
                    target: StateTarget::OwnedProcess(record.clone()),
                    expected_revision: None,
                    op: StateOp::RecordTerminationProof {
                        proof: proof.clone(),
                    },
                },
                StateMutation {
                    target: StateTarget::Attempt(AttemptId::new("att_r").expect("attempt")),
                    expected_revision: None,
                    op: StateOp::TransitionAttempt {
                        from: AttemptState::Running,
                        to: AttemptState::Cancelled,
                    },
                },
            ],
            vec![draft_a()],
            Vec::new(),
        ))
        .await
        .expect_err("the late transition fails");
    assert!(matches!(late, StateError::InvalidTransition { .. }));

    assert_eq!(
        owned_state(&store).await,
        ProcessObservedState::Running,
        "the observed state must roll back with the failed transaction"
    );
    let StateReply::AttemptView(attempt) = store
        .query(StateQuery::AttemptView {
            attempt_id: AttemptId::new("att_r").expect("attempt"),
        })
        .await
        .expect("attempt view")
    else {
        panic!("expected attempt view");
    };
    assert_eq!(attempt.record.state, AttemptState::LaunchIntent);
    let (events, verdict) = store.audit_chain().await.expect("audit chain");
    assert!(
        events.is_empty(),
        "failed proof transactions append nothing"
    );
    assert!(matches!(verdict, ChainVerdict::Empty));
    let connection = read_connection(&path);
    let evidence_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
        .expect("evidence count");
    assert_eq!(evidence_rows, 0);
    drop(connection);
    store.close().expect("close");
}

#[tokio::test]
async fn inbox_same_digest_is_a_noop_and_different_digest_conflicts() {
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

    let digest = Sha256Digest::digest(b"inbox-one");
    let mutation = |digest: Sha256Digest| StateMutation {
        target: StateTarget::Session(
            vestry_core::contracts::primitives::SessionId::new("sess_inbox").expect("session"),
        ),
        expected_revision: None,
        op: StateOp::RecordInbox {
            source: InboxSource::Trello,
            key: InboxKey(SafeCode::new("card:22:comment:1").expect("key")),
            digest,
            aggregate_sequence: 1,
        },
    };

    let first = store
        .submit(build_txn(
            "inbox-1",
            1,
            vec![mutation(digest)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("first inbox insert");
    assert_eq!(first.revisions[0].revision, Revision::INITIAL);

    let repeat = store
        .submit(build_txn(
            "inbox-2",
            1,
            vec![mutation(digest)],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("same digest is a no-op");
    assert_eq!(repeat.revisions[0].revision, Revision::INITIAL);

    let different = store
        .submit(build_txn(
            "inbox-3",
            1,
            vec![mutation(Sha256Digest::digest(b"inbox-two"))],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect_err("same key with a different digest must conflict");
    assert!(matches!(
        different,
        StateError::ConstraintViolation {
            constraint: "inbox_digest"
        }
    ));

    let connection = read_connection(&path);
    let (rows, stored): (i64, String) = connection
        .query_row("SELECT COUNT(*), MIN(digest) FROM inbox", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("inbox row");
    assert_eq!(rows, 1);
    assert_eq!(stored, digest.to_hex());
    drop(connection);
    store.close().expect("close");
}

#[tokio::test]
async fn consume_grant_binds_action_expiry_and_single_use() {
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

    let connection = read_connection(&path);
    connection
        .execute_batch(
            "INSERT INTO action_requests (action_id, goal_id, operation, state, created_at_ms)
             VALUES ('act_A', NULL, 'merge_pr', '\"pending\"', 0),
                    ('act_B', NULL, 'merge_pr', '\"pending\"', 0);
             INSERT INTO approvals (approval_id, action_id, state, expires_at_ms, consumed_at_ms,
                                    revision)
             VALUES ('appr_1', 'act_A', '\"unconsumed\"', NULL, NULL, 0),
                    ('appr_exp', 'act_A', '\"unconsumed\"', 1000, NULL, 0);",
        )
        .expect("approval fixtures");
    drop(connection);

    let consume = |approval: &str, action: &str, at: i64| {
        build_txn(
            "consume",
            1,
            vec![StateMutation {
                target: StateTarget::Approval(
                    vestry_core::contracts::primitives::ApprovalId::new(approval)
                        .expect("approval"),
                ),
                expected_revision: None,
                op: StateOp::ConsumeGrant {
                    approval_id: vestry_core::contracts::primitives::ApprovalId::new(approval)
                        .expect("approval"),
                    action_id: ActionId::new(action).expect("action"),
                    consumed_at_ms: UtcMillis(at),
                },
            }],
            Vec::new(),
            Vec::new(),
        )
    };

    let foreign = store
        .submit(consume("appr_1", "act_B", 5000))
        .await
        .expect_err("a foreign action cannot consume the grant");
    assert!(matches!(
        foreign,
        StateError::ConstraintViolation {
            constraint: "approval_action_id"
        }
    ));

    let expired = store
        .submit(consume("appr_exp", "act_A", 5000))
        .await
        .expect_err("an expired grant cannot be consumed");
    assert!(matches!(
        expired,
        StateError::InvalidTransition {
            from: "expired",
            to: "consumed"
        }
    ));

    let missing = store
        .submit(consume("appr_absent", "act_A", 5000))
        .await
        .expect_err("an unknown approval is not found");
    assert!(matches!(
        missing,
        StateError::NotFound {
            target: StateTarget::Approval(_)
        }
    ));

    let valid = store
        .submit(consume("appr_1", "act_A", 5000))
        .await
        .expect("a valid grant is consumed once");
    assert_eq!(valid.revisions[0].revision, Revision(1));

    let reused = store
        .submit(consume("appr_1", "act_A", 6000))
        .await
        .expect_err("a consumed grant is single-use");
    assert!(matches!(
        reused,
        StateError::InvalidTransition {
            from: "consumed",
            to: "consumed"
        }
    ));

    let connection = read_connection(&path);
    let (state, consumed_at, revision): (String, Option<i64>, i64) = connection
        .query_row(
            "SELECT state, consumed_at_ms, revision FROM approvals WHERE approval_id = 'appr_1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("approval row");
    assert_eq!(state, "\"consumed\"");
    assert_eq!(consumed_at, Some(5000));
    assert_eq!(revision, 1);
    drop(connection);
    store.close().expect("close");
}

#[tokio::test]
async fn recovery_view_round_trips_repository_lease_scope() {
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
            vec![launch_mutation("dsp_lease", "att_lease")],
            Vec::new(),
            Vec::new(),
        ))
        .await
        .expect("launch");

    let connection = read_connection(&path);
    connection
        .execute(
            "INSERT INTO leases (lease_id, attempt_id, kind, scope_json, generation, fence,
                                 state, revision)
             VALUES ('lease_repo', 'att_lease', '\"implementation\"', ?1, 1, 1,
                     '\"active\"', 0)",
            [r#"{"kind":"repository","worktree":"C:\\work\\repo","branch":"ves/phase-b-state-spine","base_sha":"abababababababababababababababababababab"}"#],
        )
        .expect("repository lease fixture");
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
    assert_eq!(view.leases.len(), 1);
    let lease = &view.leases[0];
    assert_eq!(lease.kind, LeaseKind::Implementation);
    assert_eq!(lease.state, LeaseState::Active);
    assert_eq!(
        lease.scope,
        LeaseScope::Repository {
            worktree: WindowsAbsolutePath::new("C:\\work\\repo").expect("worktree"),
            branch: BranchName::new("ves/phase-b-state-spine").expect("branch"),
            base_sha: GitSha::from_hex(&"ab".repeat(20)).expect("sha"),
        }
    );
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

/// F6: every reader reply is pinned to one WAL snapshot. A concurrent writer
/// commits attempt+dispatch+audit triplets; a torn reply would pair rows from
/// different commits and break the equality between these counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reader_snapshot_is_consistent_under_concurrent_writes() {
    use std::sync::Arc;

    use vestry_core::contracts::state::StateReader;

    const WRITES: usize = 24;

    let (_dir, _path, store) = temp_store();
    let store = Arc::new(store);
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

    let writer = {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            for index in 0..WRITES {
                let txn = build_txn(
                    &format!("write-{index}"),
                    1,
                    vec![launch_mutation(
                        &format!("dsp_{index}"),
                        &format!("att_{index}"),
                    )],
                    vec![draft_a()],
                    Vec::new(),
                );
                store.submit(txn).await.expect("concurrent write");
            }
        })
    };

    let mut reads = 0usize;
    loop {
        let StateReply::RecoveryView(view) = reader
            .read(StateQuery::RecoveryView {
                generation: DaemonGeneration(1),
            })
            .await
            .expect("reader query")
        else {
            panic!("expected recovery view");
        };
        assert_eq!(
            view.launch_intents.len(),
            view.dispatches.len(),
            "launch intents and dispatches must come from one snapshot"
        );
        assert_eq!(
            view.attempts.len(),
            view.dispatches.len(),
            "attempts and dispatches must come from one snapshot"
        );
        assert_eq!(
            view.audit_head.sequence.get() as usize,
            view.dispatches.len(),
            "the audit head must match the row snapshot"
        );
        for intent in &view.launch_intents {
            assert!(view
                .dispatches
                .iter()
                .any(|record| record.dispatch_id == intent.dispatch_id));
            assert!(view
                .attempts
                .iter()
                .any(|record| record.attempt_id == intent.attempt_id));
        }
        reads += 1;
        if writer.is_finished() && reads >= WRITES {
            break;
        }
        tokio::task::yield_now().await;
    }
    writer.await.expect("writer task");

    let StateReply::RecoveryView(view) = reader
        .read(StateQuery::RecoveryView {
            generation: DaemonGeneration(1),
        })
        .await
        .expect("final reader query")
    else {
        panic!("expected recovery view");
    };
    assert_eq!(view.launch_intents.len(), WRITES);
    assert_eq!(view.dispatches.len(), WRITES);
    assert_eq!(view.attempts.len(), WRITES);

    let store = Arc::try_unwrap(store).ok().expect("sole store owner");
    store.close().expect("close");
}
