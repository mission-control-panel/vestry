//! Durable state spine (LLD §8/§9, C4 §5, C7 §12, PM decision D4).
//!
//! One `std::thread` owns the only writable `rusqlite::Connection`; callers
//! talk to it through the bounded state channel. Every commit runs
//! `BEGIN IMMEDIATE` and covers state mutations, audit appends and outbox
//! intents in one transaction. A panicking writer thread closes the channel,
//! which surfaces as [`StateError::WriterUnavailable`] — never a receipt.
//!
//! Router discipline: nothing in this module is async except the channel
//! submit/read wrappers, so no SQLite call can run on a Tokio executor
//! thread.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use tokio::sync::{mpsc, oneshot};

use super::audit as audit_runtime;
use super::contracts::audit::{AuditEvent, ChainVerdict};
use super::contracts::certificate::{
    CertificateAbsentReason, CertificateInvalidReason, CertificateVerdict,
};
use super::contracts::channel::{
    MAX_STATE_TXN_BYTES, STATE_CHANNEL_CAPACITY, STATE_SUBMIT_TIMEOUT,
};
use super::contracts::dispatch::BindingKind;
use super::contracts::doctor::AdapterSessionRecord;
use super::contracts::primitives::{
    AdmissionId, AttemptId, BranchName, CertificateId, CreationFiletime, DaemonGeneration,
    DispatchId, DispatchOrdinal, Fence, FingerprintDigest, GitSha, JobGeneration, LeaseId,
    OutboxId, ProcessRecordId, Revision, SafeId, SessionId, Sha256Digest, UtcMillis,
    WindowsAbsolutePath,
};
use super::contracts::schema::{
    InternalErrorCode, MigrationId, SchemaVersion, CURRENT_SCHEMA_VERSION, EXPECTED_TABLE_COUNT,
    TABLE_NAMES,
};
use super::contracts::state::{
    AttemptRecord, AttemptView, CommitReceipt, DaemonGenerationRecord, DaemonOwnership,
    DispatchRecord, DispatchView, LaunchIntentRecord, LeaseKind, LeaseRecord, LeaseScope,
    LeaseState, ObjectRevision, OutboxIntent, OutboxRecord, OutboxState, OutboxView,
    OwnedProcessRecord, RecoveryView, StateError, StateMutation, StateOp, StateQuery, StateReader,
    StateReply, StateTarget, StateTxn, StateWriter,
};
use super::contracts::status::{
    AttemptState, DaemonGenerationState, DispatchState, EvidenceIntegrity, EvidenceType,
    ProcessObservedState, SafeArtifactRef, TaskState,
};

/// Embedded migration train. The digest is computed over the exact bytes of
/// the file as checked into git (`*.sql text eol=lf`, Q9).
const MIGRATIONS: &[(u32, &[u8])] = &[(1, include_bytes!("../migrations/0001_v1.sql"))];

/// Persisted JSON form of the only terminal approval state.
const CONSUMED_APPROVAL_STATE: &str = "\"consumed\"";

/// `schema_migrations` is insert-only (C7 §8.3.5 / §8.4): applied history is
/// never rewritten in place. The triggers are runner-owned so the migration
/// bytes (and therefore the checksum) stay exactly the DDL train.
const SCHEMA_MIGRATIONS_DDL: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at_ms INTEGER NOT NULL,
    binary_revision TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS schema_migrations_no_update
BEFORE UPDATE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'schema_migrations is insert-only');
END;
CREATE TRIGGER IF NOT EXISTS schema_migrations_no_delete
BEFORE DELETE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'schema_migrations is insert-only');
END;";

/// Builder revision persisted with each applied migration. It identifies the
/// binary that produced the DDL; it is not a security boundary.
fn binary_revision() -> &'static str {
    concat!("vestry-core-", env!("CARGO_PKG_VERSION"))
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

enum Command {
    Commit {
        txn: StateTxn,
        reply: oneshot::Sender<Result<CommitReceipt, StateError>>,
    },
    Read {
        query: StateQuery,
        reply: oneshot::Sender<Result<StateReply, StateError>>,
    },
    AuditChain {
        reply: oneshot::Sender<Result<(Vec<AuditEvent>, ChainVerdict), StateError>>,
    },
    #[cfg(test)]
    Crash,
    /// Test-only writer stall used to observe channel saturation.
    #[cfg(test)]
    Hold {
        ready: oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    },
}

/// The single-writer SQLite core. Cloning is not supported: exactly one
/// channel sender exists per store so the writer's lifetime is bounded by
/// the store.
pub struct SqliteStateStore {
    sender: Option<mpsc::Sender<Command>>,
    path: PathBuf,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl SqliteStateStore {
    /// Opens (creating if absent) the database at `path`, applies the
    /// migration train, and starts the writer thread.
    ///
    /// This function is synchronous and runs SQLite on the calling thread.
    /// Per D4 it must be called off the Tokio executor (the composition root
    /// wraps it in `spawn_blocking`); enforcement lands with B2.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|_| internal(InternalErrorCode::Io))?;
            }
        }

        let mut connection = Connection::open(&path).map_err(db_error)?;
        configure(&connection)?;
        migrate(&mut connection)?;

        let (sender, receiver) = mpsc::channel(STATE_CHANNEL_CAPACITY);
        let writer = std::thread::Builder::new()
            .name("vestry-state-writer".to_string())
            .spawn(move || writer_loop(connection, receiver))
            .map_err(|_| internal(InternalErrorCode::Io))?;

        Ok(Self {
            sender: Some(sender),
            path,
            writer: Mutex::new(Some(writer)),
        })
    }

    fn channel(&self) -> Result<&mpsc::Sender<Command>, StateError> {
        self.sender.as_ref().ok_or(StateError::WriterUnavailable)
    }

    /// Stops the writer and joins its thread. Idempotent from the caller's
    /// perspective: after `close` the store cannot be used again.
    pub fn close(mut self) -> Result<(), StateError> {
        self.sender.take();
        let handle = self
            .writer
            .lock()
            .map_err(|_| internal(InternalErrorCode::Invariant))?
            .take();
        if let Some(handle) = handle {
            handle.join().map_err(|_| internal(InternalErrorCode::Io))?;
        }
        Ok(())
    }

    /// Store path (health checks and tests only).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens the same database on a *separate* read-only connection. This is
    /// for diagnostics and tests; the durable writer path never uses it.
    pub fn open_reader(&self) -> Result<SqliteStateReader, StateError> {
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(db_error)?;
        connection
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")
            .map_err(db_error)?;
        Ok(SqliteStateReader {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Test/support hook: submits one transaction and awaits its receipt.
    pub async fn submit(&self, txn: StateTxn) -> Result<CommitReceipt, StateError> {
        if txn.estimated_bytes() > MAX_STATE_TXN_BYTES {
            return Err(StateError::TransactionTooLarge {
                limit: MAX_STATE_TXN_BYTES,
            });
        }
        let (reply, response) = oneshot::channel();
        let envelope = Command::Commit { txn, reply };
        match tokio::time::timeout(STATE_SUBMIT_TIMEOUT, self.channel()?.send(envelope)).await {
            Err(_) => Err(StateError::Backpressure {
                capacity: STATE_CHANNEL_CAPACITY,
            }),
            Ok(Err(_)) => Err(StateError::WriterUnavailable),
            Ok(Ok(())) => response.await.map_err(|_| StateError::WriterUnavailable)?,
        }
    }

    /// Test/support hook: reads a typed query through the writer thread.
    pub async fn query(&self, query: StateQuery) -> Result<StateReply, StateError> {
        let (reply, response) = oneshot::channel();
        match tokio::time::timeout(
            STATE_SUBMIT_TIMEOUT,
            self.channel()?.send(Command::Read { query, reply }),
        )
        .await
        {
            Err(_) => Err(StateError::Backpressure {
                capacity: STATE_CHANNEL_CAPACITY,
            }),
            Ok(Err(_)) => Err(StateError::WriterUnavailable),
            Ok(Ok(())) => response.await.map_err(|_| StateError::WriterUnavailable)?,
        }
    }

    /// Reads the persisted audit chain and verifies it against the stored
    /// head. Used by doctor and by the tamper tests.
    pub async fn audit_chain(&self) -> Result<(Vec<AuditEvent>, ChainVerdict), StateError> {
        let (reply, response) = oneshot::channel();
        match tokio::time::timeout(
            STATE_SUBMIT_TIMEOUT,
            self.channel()?.send(Command::AuditChain { reply }),
        )
        .await
        {
            Err(_) => Err(StateError::Backpressure {
                capacity: STATE_CHANNEL_CAPACITY,
            }),
            Ok(Err(_)) => Err(StateError::WriterUnavailable),
            Ok(Ok(())) => response.await.map_err(|_| StateError::WriterUnavailable)?,
        }
    }

    /// Test-only crash injection: the writer thread ends without answering.
    #[cfg(test)]
    pub async fn crash_writer(&self) -> Result<(), StateError> {
        self.channel()?
            .send(Command::Crash)
            .await
            .map_err(|_| StateError::WriterUnavailable)
    }
}

impl StateWriter for SqliteStateStore {
    fn submit(
        &self,
        txn: StateTxn,
    ) -> super::contracts::primitives::BoxFuture<'_, Result<CommitReceipt, StateError>> {
        Box::pin(SqliteStateStore::submit(self, txn))
    }
}

/// Read-only query surface. Each reader owns its own connection; WAL gives it
/// a consistent snapshot without touching the writer's connection.
pub struct SqliteStateReader {
    connection: Arc<Mutex<Connection>>,
}

impl StateReader for SqliteStateReader {
    fn read(
        &self,
        query: StateQuery,
    ) -> super::contracts::primitives::BoxFuture<'_, Result<StateReply, StateError>> {
        let connection = Arc::clone(&self.connection);
        Box::pin(async move {
            // SQLite runs on the blocking pool, never on the executor thread
            // that polls this future (D4).
            let joined = tokio::task::spawn_blocking(move || {
                let guard = connection
                    .lock()
                    .map_err(|_| internal(InternalErrorCode::Invariant))?;
                execute_query(&guard, query)
            })
            .await
            .map_err(|_| internal(InternalErrorCode::Io))?;
            joined
        })
    }
}

// ---------------------------------------------------------------------------
// Writer thread
// ---------------------------------------------------------------------------

fn configure(connection: &Connection) -> Result<(), StateError> {
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;",
        )
        .map_err(db_error)?;
    // C7 §8.3.8/§8.4: the settings must be *read back*, not assumed. A
    // mismatch fails closed before any migration or write can proceed.
    verify_pragmas(connection)
}

fn verify_pragmas(connection: &Connection) -> Result<(), StateError> {
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(db_error)?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(internal(InternalErrorCode::Invariant));
    }
    // `PRAGMA synchronous` reports the numeric level; FULL is 2.
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(db_error)?;
    if synchronous != 2 {
        return Err(internal(InternalErrorCode::Invariant));
    }
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(db_error)?;
    if foreign_keys != 1 {
        return Err(internal(InternalErrorCode::Invariant));
    }
    Ok(())
}

fn writer_loop(mut connection: Connection, mut receiver: mpsc::Receiver<Command>) {
    while let Some(command) = receiver.blocking_recv() {
        let keep_running = handle(&mut connection, command);
        if !keep_running {
            break;
        }
    }
}

fn handle(connection: &mut Connection, command: Command) -> bool {
    match command {
        Command::Commit { txn, reply } => {
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| commit(connection, &txn)));
            match outcome {
                Ok(result) => {
                    let _ = reply.send(result);
                    true
                }
                Err(_) => {
                    let _ = reply.send(Err(StateError::WriterUnavailable));
                    false
                }
            }
        }
        Command::Read { query, reply } => {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                execute_query(connection, query)
            }));
            match outcome {
                Ok(result) => {
                    let _ = reply.send(result);
                    true
                }
                Err(_) => {
                    let _ = reply.send(Err(StateError::WriterUnavailable));
                    false
                }
            }
        }
        Command::AuditChain { reply } => {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let events = audit_runtime::read_events(connection)?;
                let verdict = audit_runtime::verify_persisted(connection)?;
                Ok((events, verdict))
            }));
            match outcome {
                Ok(result) => {
                    let _ = reply.send(result);
                    true
                }
                Err(_) => {
                    let _ = reply.send(Err(StateError::WriterUnavailable));
                    false
                }
            }
        }
        #[cfg(test)]
        Command::Crash => panic!("injected writer crash (test only)"),
        #[cfg(test)]
        Command::Hold { ready, release } => {
            let _ = ready.send(());
            let _ = release.recv();
            true
        }
    }
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

fn migrate(connection: &mut Connection) -> Result<(), StateError> {
    connection
        .execute_batch(SCHEMA_MIGRATIONS_DDL)
        .map_err(db_error)?;

    let applied: Vec<(u32, String)> = {
        let mut statement = connection
            .prepare("SELECT version, checksum FROM schema_migrations ORDER BY version ASC")
            .map_err(db_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)? as u32, row.get::<_, String>(1)?))
            })
            .map_err(db_error)?;
        let mut collected = Vec::new();
        for row in rows {
            collected.push(row.map_err(db_error)?);
        }
        collected
    };

    if let Some((version, _)) = applied.last() {
        if *version > CURRENT_SCHEMA_VERSION.0 {
            return Err(StateError::SchemaNewer {
                found: SchemaVersion(*version),
                supported: CURRENT_SCHEMA_VERSION,
            });
        }
    }

    for (version, checksum) in &applied {
        let Some((_, bytes)) = MIGRATIONS
            .iter()
            .find(|(candidate, _)| candidate == version)
        else {
            return Err(internal(InternalErrorCode::Invariant));
        };
        if Sha256Digest::digest(bytes).to_hex() != *checksum {
            return Err(StateError::MigrationChecksumMismatch {
                migration: MigrationId(*version),
            });
        }
    }

    for (version, bytes) in MIGRATIONS {
        if applied.iter().any(|(done, _)| done == version) {
            continue;
        }
        let sql = std::str::from_utf8(bytes).map_err(|_| internal(InternalErrorCode::Invariant))?;
        let tx = connection.transaction().map_err(db_error)?;
        tx.execute_batch(sql).map_err(db_error)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, checksum, applied_at_ms, binary_revision)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                *version as i64,
                Sha256Digest::digest(bytes).to_hex(),
                now_ms().0,
                binary_revision(),
            ],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)?;
    }

    // C7 §8.3.4/§8.4 startup verification. These are returning checks, not
    // `debug_assert`s: release builds must enforce them just as strictly.
    let present = table_names(connection)?;
    if present.len() != EXPECTED_TABLE_COUNT {
        return Err(internal(InternalErrorCode::Invariant));
    }
    for expected in TABLE_NAMES {
        if !present.iter().any(|name| name == expected) {
            return Err(internal(InternalErrorCode::Invariant));
        }
    }
    let fk_violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(db_error)?;
    if fk_violations != 0 {
        return Err(internal(InternalErrorCode::Invariant));
    }
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(db_error)?;
    if integrity != "ok" {
        return Err(internal(InternalErrorCode::Invariant));
    }
    verify_pragmas(connection)?;
    Ok(())
}

fn table_names(connection: &Connection) -> Result<Vec<String>, StateError> {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .map_err(db_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(db_error)?;
    let mut names = Vec::new();
    for row in rows {
        names.push(row.map_err(db_error)?);
    }
    Ok(names)
}

// ---------------------------------------------------------------------------
// Commit path
// ---------------------------------------------------------------------------

fn commit(connection: &mut Connection, txn: &StateTxn) -> Result<CommitReceipt, StateError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(db_error)?;

    enforce_generation(&transaction, txn)?;

    let mut revisions = Vec::with_capacity(txn.mutations().len());
    for mutation in txn.mutations() {
        revisions.push(apply_mutation(&transaction, txn, mutation)?);
    }

    validate_termination_proofs(&transaction, txn)?;

    let committed_at_ms = now_ms();
    let head = audit_runtime::current_head(&transaction)?;
    let appended = audit_runtime::append(&transaction, txn.audit(), head, committed_at_ms)?;

    for intent in txn.outbox() {
        insert_outbox(&transaction, intent)?;
    }

    transaction.commit().map_err(db_error)?;

    Ok(CommitReceipt {
        request_id: txn.request_id().clone(),
        generation: txn.generation(),
        committed_at_ms,
        audit_sequence: appended.last_sequence,
        audit_head: appended.head,
        revisions,
    })
}

/// D5 / T45 §10.5: a recorded termination proof is only authoritative when
/// its evidence row commits in the same transaction, an audit event references
/// it, and the target owned process is the one the proof names. Otherwise the
/// whole transaction rolls back; no `Terminated` claim survives without its
/// authority chain.
fn validate_termination_proofs(
    transaction: &Transaction<'_>,
    txn: &StateTxn,
) -> Result<(), StateError> {
    for mutation in txn.mutations() {
        let StateOp::RecordTerminationProof { proof } = &mutation.op else {
            continue;
        };
        let StateTarget::OwnedProcess(record_id) = &mutation.target else {
            return Err(StateError::ConstraintViolation {
                constraint: "termination_proof_target",
            });
        };
        let evidence = txn
            .mutations()
            .iter()
            .find_map(|candidate| match (&candidate.op, &candidate.target) {
                (StateOp::InsertEvidence { evidence }, StateTarget::Evidence(id))
                    if *id == proof.evidence_id =>
                {
                    Some(evidence)
                }
                _ => None,
            })
            .ok_or(StateError::ConstraintViolation {
                constraint: "termination_proof_evidence",
            })?;
        if txn.audit().is_empty() {
            return Err(StateError::ConstraintViolation {
                constraint: "termination_proof_audit",
            });
        }
        if evidence.evidence_type != EvidenceType::TerminationProof
            || evidence.redaction_version != proof.redaction_version
        {
            return Err(StateError::ConstraintViolation {
                constraint: "termination_proof_evidence",
            });
        }
        // Only `Verified` may support a PASS; an incomplete/unavailable proof
        // is `Unavailable` and can never claim termination (T45 C10.5).
        let expected_integrity = if proof.is_complete() {
            EvidenceIntegrity::Verified
        } else {
            EvidenceIntegrity::Unavailable
        };
        if evidence.integrity != expected_integrity {
            return Err(StateError::ConstraintViolation {
                constraint: "termination_proof_integrity",
            });
        }
        let binding: Option<(String, String)> = transaction
            .query_row(
                "SELECT o.dispatch_id, d.attempt_id
                 FROM owned_processes o
                 JOIN dispatches d ON d.dispatch_id = o.dispatch_id
                 WHERE o.process_record_id = ?1",
                params![record_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db_error)?;
        match binding {
            Some((dispatch, attempt))
                if dispatch == proof.dispatch_id.as_str()
                    && attempt == proof.attempt_id.as_str() => {}
            Some(_) => {
                return Err(StateError::ConstraintViolation {
                    constraint: "termination_proof_dispatch",
                })
            }
            None => {
                return Err(StateError::NotFound {
                    target: mutation.target.clone(),
                })
            }
        }
    }
    Ok(())
}

fn enforce_generation(transaction: &Transaction<'_>, txn: &StateTxn) -> Result<(), StateError> {
    let current: Option<u64> = transaction
        .query_row(
            "SELECT generation FROM daemon_generations ORDER BY generation DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(db_error)?
        .map(|value| value as u64);

    let begins = txn
        .mutations()
        .iter()
        .any(|mutation| matches!(mutation.op, StateOp::BeginDaemonGeneration { .. }));

    // T45 §10.1: a restart acquires the *next* generation (clean or unclean
    // prior shutdown alike); every other operation must target the current
    // one. A begin at the current generation is a duplicate, not a restart.
    match (current, begins) {
        (Some(current), true) => {
            let next = current
                .checked_add(1)
                .map(DaemonGeneration)
                .ok_or_else(|| internal(InternalErrorCode::Invariant))?;
            if txn.generation() != next {
                return Err(StateError::NotCurrentGeneration {
                    expected: next,
                    found: txn.generation(),
                });
            }
            Ok(())
        }
        (Some(current), false) if DaemonGeneration(current) != txn.generation() => {
            Err(StateError::NotCurrentGeneration {
                expected: DaemonGeneration(current),
                found: txn.generation(),
            })
        }
        (None, true) if txn.generation() != DaemonGeneration(1) => {
            Err(StateError::NotCurrentGeneration {
                expected: DaemonGeneration(1),
                found: txn.generation(),
            })
        }
        (None, false) => Err(StateError::NotCurrentGeneration {
            expected: DaemonGeneration(0),
            found: txn.generation(),
        }),
        _ => Ok(()),
    }
}

fn apply_mutation(
    transaction: &Transaction<'_>,
    txn: &StateTxn,
    mutation: &StateMutation,
) -> Result<ObjectRevision, StateError> {
    let target = &mutation.target;
    match (&mutation.op, target) {
        (StateOp::BeginDaemonGeneration { started_at_ms }, StateTarget::DaemonGeneration) => {
            let exists: Option<i64> = transaction
                .query_row(
                    "SELECT generation FROM daemon_generations WHERE generation = ?1",
                    params![txn.generation().get() as i64],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            if exists.is_some() {
                return Err(StateError::ConstraintViolation {
                    constraint: "daemon_generations_generation",
                });
            }
            transaction
                .execute(
                    "INSERT INTO daemon_generations
                         (generation, started_at_ms, clean_shutdown, state, revision)
                     VALUES (?1, ?2, 0, ?3, 0)",
                    params![
                        txn.generation().get() as i64,
                        started_at_ms.0,
                        json(&DaemonGenerationState::Starting)?,
                    ],
                )
                .map_err(db_error)?;
            Ok(ObjectRevision {
                target: target.clone(),
                revision: Revision::INITIAL,
            })
        }

        (StateOp::MarkCleanShutdown { .. }, StateTarget::DaemonGeneration) => {
            let current = require_revision(
                transaction,
                target,
                mutation.expected_revision,
                txn.generation(),
            )?;
            let revision = current.next();
            let changed = transaction
                .execute(
                    "UPDATE daemon_generations
                     SET clean_shutdown = 1, state = ?2, revision = ?3
                     WHERE generation = ?1",
                    params![
                        txn.generation().get() as i64,
                        json(&DaemonGenerationState::CleanStopped)?,
                        revision.get() as i64,
                    ],
                )
                .map_err(db_error)?;
            if changed != 1 {
                return Err(StateError::NotFound {
                    target: target.clone(),
                });
            }
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (
            StateOp::RecordLaunchIntent {
                dispatch_id,
                attempt_id,
                admission_id,
                manifest_id,
                canary_id,
                lease_id,
                fence,
                intent_state,
            },
            StateTarget::Dispatch(target_id),
        ) if target_id == dispatch_id => {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO attempts
                         (attempt_id, run_id, state, retry_count, revision)
                     VALUES (?1, NULL, ?2, 0, 0)",
                    params![attempt_id.as_str(), json(&AttemptState::LaunchIntent)?],
                )
                .map_err(db_error)?;
            // The frozen op carries no ordinal input; T45 fixes the first
            // dispatch of an attempt at `DispatchOrdinal(1)`. A second
            // dispatch per attempt is a recorded B1.2 limitation
            // (`UNIQUE(attempt_id, ordinal)`).
            let insert_dispatch = format!(
                "INSERT INTO dispatches
                     (dispatch_id, attempt_id, ordinal, binding_kind, state, session_id,
                      admission_id, manifest_id, canary_id, lease_id, fence, intent_state,
                      created_at_ms, revision)
                 VALUES (?1, ?2, {}, ?3, ?4, NULL, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0)",
                DispatchOrdinal::FIRST.get()
            );
            transaction
                .execute(
                    &insert_dispatch,
                    params![
                        dispatch_id.as_str(),
                        attempt_id.as_str(),
                        json(&BindingKind::AnchoredInvocation)?,
                        json(&DispatchState::LaunchIntent)?,
                        admission_id.as_str(),
                        manifest_id.as_str(),
                        canary_id.as_str(),
                        lease_id.as_ref().map(|id| id.as_str().to_string()),
                        fence.get() as i64,
                        json(intent_state)?,
                        txn.submitted_at_ms().0,
                    ],
                )
                .map_err(|error| map_constraint(error, "dispatches"))?;
            // F10: the attempt points at its current dispatch so
            // `AttemptView.active_dispatch` is not permanently empty.
            transaction
                .execute(
                    "UPDATE attempts SET active_dispatch_id = ?2 WHERE attempt_id = ?1",
                    params![attempt_id.as_str(), dispatch_id.as_str()],
                )
                .map_err(db_error)?;
            Ok(ObjectRevision {
                target: target.clone(),
                revision: Revision::INITIAL,
            })
        }

        (
            StateOp::RecordProcessIdentity {
                dispatch_id,
                identity,
                executable_digest,
                job_generation,
                observed_state,
            },
            StateTarget::OwnedProcess(_),
        ) => {
            let record_id = process_record_id(target)?;
            // R5: the dispatch may already be bound to a different process
            // record id. Silently retargeting it would rewrite ownership and
            // regress the stored revision, so the id must match.
            let bound: Option<String> = transaction
                .query_row(
                    "SELECT process_record_id FROM owned_processes WHERE dispatch_id = ?1",
                    params![dispatch_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            let revision = match bound.as_deref() {
                Some(stored) if stored != record_id.as_str() => {
                    return Err(StateError::ConstraintViolation {
                        constraint: "owned_processes_process_record_id",
                    })
                }
                Some(_) => require_revision(
                    transaction,
                    target,
                    mutation.expected_revision,
                    txn.generation(),
                )?
                .next(),
                None => match mutation.expected_revision {
                    Some(expected) => {
                        return Err(StateError::Conflict {
                            target: target.clone(),
                            expected,
                            actual: Revision::INITIAL,
                        })
                    }
                    None => Revision::INITIAL,
                },
            };
            transaction
                .execute(
                    "INSERT INTO owned_processes
                         (process_record_id, dispatch_id, identity_pid,
                          identity_creation_filetime, executable_digest, job_generation,
                          observed_state, revision)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(dispatch_id) DO UPDATE SET
                         identity_pid = excluded.identity_pid,
                         identity_creation_filetime = excluded.identity_creation_filetime,
                         executable_digest = excluded.executable_digest,
                         job_generation = excluded.job_generation,
                         observed_state = excluded.observed_state,
                         revision = excluded.revision",
                    params![
                        record_id.as_str(),
                        dispatch_id.as_str(),
                        identity.pid as i64,
                        identity.creation_filetime.0 as i64,
                        executable_digest.to_hex(),
                        job_generation.get() as i64,
                        json(observed_state)?,
                        revision.get() as i64,
                    ],
                )
                .map_err(|error| map_constraint(error, "owned_processes"))?;
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (StateOp::UpdateOwnedProcessState { observed_state }, StateTarget::OwnedProcess(_)) => {
            let current = require_revision(
                transaction,
                target,
                mutation.expected_revision,
                txn.generation(),
            )?;
            let revision = current.next();
            let changed = transaction
                .execute(
                    "UPDATE owned_processes SET observed_state = ?2, revision = ?3
                     WHERE process_record_id = ?1",
                    params![
                        process_record_id(target)?.as_str(),
                        json(observed_state)?,
                        revision.get() as i64,
                    ],
                )
                .map_err(db_error)?;
            if changed != 1 {
                return Err(StateError::NotFound {
                    target: target.clone(),
                });
            }
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (StateOp::TransitionAttempt { from, to }, StateTarget::Attempt(attempt_id)) => {
            let current: Option<String> = transaction
                .query_row(
                    "SELECT state FROM attempts WHERE attempt_id = ?1",
                    params![attempt_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            let Some(current) = current else {
                return Err(StateError::NotFound {
                    target: target.clone(),
                });
            };
            let current: AttemptState = parse_json(&current)?;
            if current != *from {
                return Err(StateError::InvalidTransition {
                    from: attempt_label(current),
                    to: attempt_label(*to),
                });
            }
            let revision = require_revision(
                transaction,
                target,
                mutation.expected_revision,
                txn.generation(),
            )?
            .next();
            transaction
                .execute(
                    "UPDATE attempts SET state = ?2, revision = ?3 WHERE attempt_id = ?1",
                    params![attempt_id.as_str(), json(to)?, revision.get() as i64],
                )
                .map_err(db_error)?;
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (StateOp::TransitionDispatch { from, to }, StateTarget::Dispatch(dispatch_id)) => {
            let current: Option<String> = transaction
                .query_row(
                    "SELECT state FROM dispatches WHERE dispatch_id = ?1",
                    params![dispatch_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            let Some(current) = current else {
                return Err(StateError::NotFound {
                    target: target.clone(),
                });
            };
            let current: DispatchState = parse_json(&current)?;
            if current != *from {
                return Err(StateError::InvalidTransition {
                    from: dispatch_label(current),
                    to: dispatch_label(*to),
                });
            }
            let revision = require_revision(
                transaction,
                target,
                mutation.expected_revision,
                txn.generation(),
            )?
            .next();
            transaction
                .execute(
                    "UPDATE dispatches SET state = ?2, revision = ?3 WHERE dispatch_id = ?1",
                    params![dispatch_id.as_str(), json(to)?, revision.get() as i64],
                )
                .map_err(db_error)?;
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (StateOp::TransitionTask { from, to }, StateTarget::Task(task_id)) => {
            let current: Option<String> = transaction
                .query_row(
                    "SELECT state FROM tasks WHERE task_id = ?1",
                    params![task_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            let Some(current) = current else {
                return Err(StateError::NotFound {
                    target: target.clone(),
                });
            };
            let current: TaskState = parse_json(&current)?;
            if current != *from {
                return Err(StateError::InvalidTransition {
                    from: task_label(current),
                    to: task_label(*to),
                });
            }
            let revision = require_revision(
                transaction,
                target,
                mutation.expected_revision,
                txn.generation(),
            )?
            .next();
            transaction
                .execute(
                    "UPDATE tasks SET state = ?2, revision = ?3 WHERE task_id = ?1",
                    params![task_id.as_str(), json(to)?, revision.get() as i64],
                )
                .map_err(db_error)?;
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (StateOp::ParkRecoveryRequired { reason, finding }, StateTarget::Attempt(attempt_id)) => {
            let revision = require_revision(
                transaction,
                target,
                mutation.expected_revision,
                txn.generation(),
            )?
            .next();
            let changed = transaction
                .execute(
                    "UPDATE attempts
                     SET state = ?2, recovery_reason = ?3, recovery_finding_id = ?4,
                         revision = ?5
                     WHERE attempt_id = ?1",
                    params![
                        attempt_id.as_str(),
                        json(&AttemptState::RecoveryRequired)?,
                        json(reason)?,
                        finding.as_str(),
                        revision.get() as i64,
                    ],
                )
                .map_err(db_error)?;
            if changed != 1 {
                return Err(StateError::NotFound {
                    target: target.clone(),
                });
            }
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (StateOp::InsertEvidence { evidence }, StateTarget::Evidence(evidence_id))
            if evidence_id == &evidence.evidence_id =>
        {
            let revision = Revision(evidence.revision.get());
            transaction
                .execute(
                    "INSERT INTO evidence
                         (evidence_id, artefact, evidence_type, producer, revision,
                          redaction_version, integrity, created_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        evidence.evidence_id.as_str(),
                        json(&ArtifactJson::from(&evidence.artefact))?,
                        json(&evidence.evidence_type)?,
                        json(&evidence.producer)?,
                        evidence.revision.get() as i64,
                        evidence.redaction_version.get() as i64,
                        json(&evidence.integrity)?,
                        evidence.created_at_ms.0,
                    ],
                )
                .map_err(|error| map_constraint(error, "evidence"))?;
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (StateOp::RecordTerminationProof { proof }, StateTarget::OwnedProcess(_)) => {
            proof
                .validate()
                .map_err(|_| StateError::ConstraintViolation {
                    constraint: "termination_proof",
                })?;
            let record_id = process_record_id(target)?;
            let exists: Option<i64> = transaction
                .query_row(
                    "SELECT 1 FROM owned_processes WHERE process_record_id = ?1",
                    params![record_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            if exists.is_none() {
                return Err(StateError::NotFound {
                    target: target.clone(),
                });
            }
            let observed = if proof.is_complete() {
                ProcessObservedState::Terminated
            } else {
                ProcessObservedState::RecoveryRequired
            };
            let revision = require_revision(
                transaction,
                target,
                mutation.expected_revision,
                txn.generation(),
            )?
            .next();
            transaction
                .execute(
                    "UPDATE owned_processes SET observed_state = ?2, revision = ?3
                     WHERE process_record_id = ?1",
                    params![record_id.as_str(), json(&observed)?, revision.get() as i64,],
                )
                .map_err(db_error)?;
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (
            StateOp::ConsumeGrant {
                approval_id,
                action_id,
                consumed_at_ms,
            },
            StateTarget::Approval(target_id),
        ) if target_id == approval_id => {
            let stored: Option<(Option<String>, String, Option<i64>)> = transaction
                .query_row(
                    "SELECT action_id, state, expires_at_ms FROM approvals
                     WHERE approval_id = ?1",
                    params![approval_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(db_error)?;
            let Some((stored_action, stored_state, expires_at_ms)) = stored else {
                return Err(StateError::NotFound {
                    target: target.clone(),
                });
            };
            // LLD 95/101/142: a grant is bound to one action, expires and is
            // single-use.
            if stored_action.as_deref() != Some(action_id.as_str()) {
                return Err(StateError::ConstraintViolation {
                    constraint: "approval_action_id",
                });
            }
            if stored_state == CONSUMED_APPROVAL_STATE {
                return Err(StateError::InvalidTransition {
                    from: "consumed",
                    to: "consumed",
                });
            }
            if expires_at_ms.is_some_and(|expiry| expiry <= consumed_at_ms.0) {
                return Err(StateError::InvalidTransition {
                    from: "expired",
                    to: "consumed",
                });
            }
            let revision = require_revision(
                transaction,
                target,
                mutation.expected_revision,
                txn.generation(),
            )?
            .next();
            let changed = transaction
                .execute(
                    "UPDATE approvals
                     SET state = ?4, consumed_at_ms = ?2, revision = ?5
                     WHERE approval_id = ?1 AND action_id = ?3
                       AND state <> ?4
                       AND (expires_at_ms IS NULL OR expires_at_ms > ?2)",
                    params![
                        approval_id.as_str(),
                        consumed_at_ms.0,
                        action_id.as_str(),
                        CONSUMED_APPROVAL_STATE,
                        revision.get() as i64,
                    ],
                )
                .map_err(db_error)?;
            if changed != 1 {
                return Err(internal(InternalErrorCode::Invariant));
            }
            Ok(ObjectRevision {
                target: target.clone(),
                revision,
            })
        }

        (
            StateOp::RecordInbox {
                source,
                key,
                digest,
                aggregate_sequence,
            },
            StateTarget::Session(_) | StateTarget::Outbox(_),
        ) => {
            let inbox_id = format!("inbox:{}:{}", source_label(*source), key.0.as_str());
            // LLD 153: a duplicate with the same digest is a no-op; the same
            // key with a different digest is a conflict, never a silent drop.
            // `inbox` rows carry no revision column, so the no-op receipt is
            // the only representable revision (`INITIAL`), matching the
            // stored row.
            let stored: Option<String> = transaction
                .query_row(
                    "SELECT digest FROM inbox WHERE source = ?1 AND inbox_key = ?2",
                    params![json(source)?, json(key)?],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            match stored {
                Some(stored) if stored != digest.to_hex() => {
                    return Err(StateError::ConstraintViolation {
                        constraint: "inbox_digest",
                    })
                }
                Some(_) => {}
                None => {
                    transaction
                        .execute(
                            "INSERT INTO inbox
                                 (inbox_id, source, inbox_key, digest, aggregate_sequence,
                                  received_at_ms)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            params![
                                inbox_id,
                                json(source)?,
                                json(key)?,
                                digest.to_hex(),
                                *aggregate_sequence as i64,
                                txn.submitted_at_ms().0,
                            ],
                        )
                        .map_err(|error| map_constraint(error, "inbox"))?;
                }
            }
            Ok(ObjectRevision {
                target: target.clone(),
                revision: Revision::INITIAL,
            })
        }

        _ => Err(StateError::ConstraintViolation {
            constraint: "unsupported_state_operation",
        }),
    }
}

fn insert_outbox(transaction: &Transaction<'_>, intent: &OutboxIntent) -> Result<(), StateError> {
    transaction
        .execute(
            "INSERT INTO outbox
                 (outbox_id, destination, outbox_key, aggregate_sequence, payload_digest,
                  state, last_observed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
             ON CONFLICT(destination, outbox_key) DO UPDATE SET
                 aggregate_sequence = excluded.aggregate_sequence,
                 payload_digest = excluded.payload_digest,
                 state = excluded.state",
            params![
                intent.outbox_id.as_str(),
                json(&intent.destination)?,
                json(&intent.key)?,
                intent.aggregate_sequence as i64,
                intent.payload_digest.to_hex(),
                json(&intent.state)?,
            ],
        )
        .map_err(|error| map_constraint(error, "outbox"))?;
    Ok(())
}

fn require_revision(
    transaction: &Transaction<'_>,
    target: &StateTarget,
    expected: Option<Revision>,
    generation: DaemonGeneration,
) -> Result<Revision, StateError> {
    let current = stored_revision(transaction, target, generation)?;
    match expected {
        Some(expected) if expected != current => Err(StateError::Conflict {
            target: target.clone(),
            expected,
            actual: current,
        }),
        _ => Ok(current),
    }
}

fn stored_revision(
    transaction: &Transaction<'_>,
    target: &StateTarget,
    generation: DaemonGeneration,
) -> Result<Revision, StateError> {
    let (table, column, key) = match target {
        StateTarget::DaemonGeneration => (
            "daemon_generations",
            "generation",
            generation.get().to_string(),
        ),
        StateTarget::Attempt(id) => ("attempts", "attempt_id", id.as_str().to_string()),
        StateTarget::Dispatch(id) => ("dispatches", "dispatch_id", id.as_str().to_string()),
        StateTarget::Task(id) => ("tasks", "task_id", id.as_str().to_string()),
        StateTarget::Lease(id) => ("leases", "lease_id", id.as_str().to_string()),
        StateTarget::OwnedProcess(id) => (
            "owned_processes",
            "process_record_id",
            id.as_str().to_string(),
        ),
        StateTarget::Evidence(id) => ("evidence", "evidence_id", id.as_str().to_string()),
        StateTarget::Outbox(id) => ("outbox", "outbox_id", id.as_str().to_string()),
        StateTarget::Approval(id) => ("approvals", "approval_id", id.as_str().to_string()),
        StateTarget::Session(_) | StateTarget::AuditChain => {
            return Err(StateError::ConstraintViolation {
                constraint: "unsupported_state_target",
            })
        }
    };
    let sql = format!("SELECT revision FROM {table} WHERE {column} = ?1");
    let revision: Option<i64> = transaction
        .query_row(&sql, params![key], |row| row.get(0))
        .optional()
        .map_err(db_error)?;
    Ok(revision
        .map(|value| Revision(value as u64))
        .unwrap_or(Revision::INITIAL))
}

fn process_record_id(target: &StateTarget) -> Result<&ProcessRecordId, StateError> {
    match target {
        StateTarget::OwnedProcess(id) => Ok(id),
        _ => Err(internal(InternalErrorCode::Invariant)),
    }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

fn execute_query(connection: &Connection, query: StateQuery) -> Result<StateReply, StateError> {
    // F6: a reader reply can be built from many SELECTs (`RecoveryView` reads
    // nine tables). A DEFERRED read transaction pins one WAL snapshot so the
    // reply cannot pair rows from different commits.
    let snapshot = connection.unchecked_transaction().map_err(db_error)?;
    let reply = execute_query_inner(&snapshot, query)?;
    snapshot.commit().map_err(db_error)?;
    Ok(reply)
}

fn execute_query_inner(
    connection: &Connection,
    query: StateQuery,
) -> Result<StateReply, StateError> {
    match query {
        StateQuery::CurrentOwnership => {
            Ok(StateReply::CurrentOwnership(current_ownership(connection)?))
        }
        StateQuery::RecoveryView { generation } => Ok(StateReply::RecoveryView(recovery_view(
            connection, generation,
        )?)),
        StateQuery::DispatchView { dispatch_id } => Ok(StateReply::DispatchView(dispatch_view(
            connection,
            &dispatch_id,
        )?)),
        StateQuery::AttemptView { attempt_id } => Ok(StateReply::AttemptView(attempt_view(
            connection,
            &attempt_id,
        )?)),
        StateQuery::AuditHead => Ok(StateReply::AuditHead(audit_runtime::current_head(
            connection,
        )?)),
        StateQuery::ReadinessCertificate {
            certificate_id,
            input_fingerprint,
        } => Ok(StateReply::ReadinessCertificate(readiness_verdict(
            connection,
            &certificate_id,
            input_fingerprint,
        )?)),
        StateQuery::OutboxView { outbox_id } => {
            Ok(StateReply::OutboxView(outbox_view(connection, &outbox_id)?))
        }
    }
}

fn current_ownership(connection: &Connection) -> Result<DaemonOwnership, StateError> {
    let rows: Vec<(i64, i64)> = {
        let mut statement = connection
            .prepare(
                "SELECT generation, clean_shutdown FROM daemon_generations
                 ORDER BY generation DESC LIMIT 2",
            )
            .map_err(db_error)?;
        let mapped = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(db_error)?;
        let mut collected = Vec::new();
        for row in mapped {
            collected.push(row.map_err(db_error)?);
        }
        collected
    };
    let Some((current, _)) = rows.first().copied() else {
        return Err(StateError::NotFound {
            target: StateTarget::DaemonGeneration,
        });
    };
    Ok(DaemonOwnership {
        generation: DaemonGeneration(current as u64),
        previous_generation: rows
            .get(1)
            .map(|(generation, _)| DaemonGeneration(*generation as u64)),
        previous_clean_shutdown: rows.get(1).map(|(_, clean)| *clean != 0),
        schema: CURRENT_SCHEMA_VERSION,
    })
}

fn recovery_view(
    connection: &Connection,
    generation: DaemonGeneration,
) -> Result<RecoveryView, StateError> {
    let daemon = connection
        .query_row(
            "SELECT started_at_ms, clean_shutdown, state FROM daemon_generations
             WHERE generation = ?1",
            params![generation.get() as i64],
            |row| {
                Ok(DaemonGenerationRecord {
                    generation,
                    started_at_ms: UtcMillis(row.get(0)?),
                    clean_shutdown: row.get::<_, i64>(1)? != 0,
                    state: DaemonGenerationState::Starting,
                })
            },
        )
        .optional()
        .map_err(db_error)?
        .ok_or(StateError::NotFound {
            target: StateTarget::DaemonGeneration,
        })?;
    let state_text: String = connection
        .query_row(
            "SELECT state FROM daemon_generations WHERE generation = ?1",
            params![generation.get() as i64],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let daemon = DaemonGenerationRecord {
        state: parse_json(&state_text)?,
        ..daemon
    };

    let launch_intents = {
        let mut statement = connection
            .prepare(
                "SELECT dispatch_id, attempt_id, admission_id, fence, intent_state
                 FROM dispatches
                 WHERE intent_state IS NOT NULL AND admission_id IS NOT NULL
                 ORDER BY created_at_ms, dispatch_id",
            )
            .map_err(db_error)?;
        let mapped = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(db_error)?;
        let mut collected = Vec::new();
        for row in mapped {
            let (dispatch, attempt, admission, fence, intent) = row.map_err(db_error)?;
            collected.push(LaunchIntentRecord {
                dispatch_id: DispatchId::new(dispatch).map_err(|_| decode_error())?,
                attempt_id: AttemptId::new(attempt).map_err(|_| decode_error())?,
                admission_id: AdmissionId::new(admission).map_err(|_| decode_error())?,
                fence: Fence(fence as u64),
                intent_state: parse_json(&intent)?,
            });
        }
        collected
    };

    let owned_processes = {
        let mut statement = connection
            .prepare(
                "SELECT process_record_id, dispatch_id, identity_pid,
                        identity_creation_filetime, executable_digest, job_generation,
                        observed_state
                 FROM owned_processes ORDER BY process_record_id",
            )
            .map_err(db_error)?;
        let mapped = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(db_error)?;
        let mut collected = Vec::new();
        for row in mapped {
            let (record, dispatch, pid, filetime, digest, job, observed) = row.map_err(db_error)?;
            let identity = match (pid, filetime) {
                (Some(pid), Some(filetime)) => Some(super::contracts::process::ProcessIdentity {
                    pid: pid as u32,
                    creation_filetime: CreationFiletime(filetime as u64),
                }),
                _ => None,
            };
            let dispatch_id = dispatch.ok_or(StateError::ConstraintViolation {
                constraint: "owned_processes_dispatch_id",
            })?;
            collected.push(OwnedProcessRecord {
                process_record_id: ProcessRecordId::new(record).map_err(|_| decode_error())?,
                dispatch_id: DispatchId::new(dispatch_id).map_err(|_| decode_error())?,
                identity,
                executable_digest: Sha256Digest::from_hex(&digest).map_err(|_| decode_error())?,
                job_generation: JobGeneration(job as u64),
                observed_state: parse_json(&observed)?,
            });
        }
        collected
    };

    let leases = {
        let mut statement = connection
            .prepare(
                "SELECT lease_id, attempt_id, kind, scope_json, fence, state
                 FROM leases WHERE generation = ?1 ORDER BY lease_id",
            )
            .map_err(db_error)?;
        let mapped = statement
            .query_map(params![generation.get() as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(db_error)?;
        let mut collected = Vec::new();
        for row in mapped {
            let (lease, attempt, kind, scope, fence, state) = row.map_err(db_error)?;
            let attempt_id = attempt.ok_or(StateError::ConstraintViolation {
                constraint: "leases_attempt_id",
            })?;
            collected.push(LeaseRecord {
                lease_id: LeaseId::new(lease).map_err(|_| decode_error())?,
                attempt_id: AttemptId::new(attempt_id).map_err(|_| decode_error())?,
                kind: parse_lease_kind(&kind)?,
                scope: parse_lease_scope(&scope)?,
                generation,
                fence: Fence(fence as u64),
                state: parse_lease_state(&state)?,
            });
        }
        collected
    };

    let attempts = {
        let mut statement = connection
            .prepare("SELECT attempt_id, state, retry_count FROM attempts ORDER BY attempt_id")
            .map_err(db_error)?;
        let mapped = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(db_error)?;
        let mut collected = Vec::new();
        for row in mapped {
            let (attempt, state, retry) = row.map_err(db_error)?;
            collected.push(AttemptRecord {
                attempt_id: AttemptId::new(attempt).map_err(|_| decode_error())?,
                state: parse_json(&state)?,
                retry_count: retry.clamp(0, 255) as u8,
            });
        }
        collected
    };

    let dispatches = {
        let mut statement = connection
            .prepare(
                "SELECT dispatch_id, attempt_id, ordinal, binding_kind, state, session_id
                 FROM dispatches ORDER BY attempt_id, ordinal",
            )
            .map_err(db_error)?;
        let mapped = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(db_error)?;
        let mut collected = Vec::new();
        for row in mapped {
            let (dispatch, attempt, ordinal, binding, state, session) = row.map_err(db_error)?;
            collected.push(DispatchRecord {
                dispatch_id: DispatchId::new(dispatch).map_err(|_| decode_error())?,
                attempt_id: AttemptId::new(attempt).map_err(|_| decode_error())?,
                ordinal: DispatchOrdinal(ordinal as u32),
                binding_kind: parse_json(&binding)?,
                state: parse_json(&state)?,
                session_id: session
                    .map(|value| SessionId::new(value).map_err(|_| decode_error()))
                    .transpose()?,
            });
        }
        collected
    };

    let adapter_sessions = {
        let mut statement = connection
            .prepare(
                "SELECT store_id, attempt_id, absolute_identity, session_id, export_state
                 FROM adapter_stores ORDER BY store_id",
            )
            .map_err(db_error)?;
        let mapped = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(db_error)?;
        let mut collected = Vec::new();
        for row in mapped {
            let (store, attempt, identity, session, export) = row.map_err(db_error)?;
            let attempt_id = attempt.ok_or(StateError::ConstraintViolation {
                constraint: "adapter_stores_attempt_id",
            })?;
            collected.push(AdapterSessionRecord {
                store_id: SafeId::new(store).map_err(|_| decode_error())?,
                attempt_id: AttemptId::new(attempt_id).map_err(|_| decode_error())?,
                absolute_identity: WindowsAbsolutePath::new(identity)
                    .map_err(|_| decode_error())?,
                session_id: session
                    .map(|value| SessionId::new(value).map_err(|_| decode_error()))
                    .transpose()?,
                export_state: parse_json(&export)?,
            });
        }
        collected
    };

    let pending_outbox = {
        let mut statement = connection
            .prepare(
                "SELECT outbox_id, destination, outbox_key, aggregate_sequence
                 FROM outbox WHERE state = ?1 ORDER BY aggregate_sequence, outbox_id",
            )
            .map_err(db_error)?;
        let mapped = statement
            .query_map(params![json(&OutboxState::Pending)?], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(db_error)?;
        let mut collected = Vec::new();
        for row in mapped {
            let (outbox, destination, key, sequence) = row.map_err(db_error)?;
            collected.push(OutboxRecord {
                outbox_id: OutboxId::new(outbox).map_err(|_| decode_error())?,
                destination: parse_json(&destination)?,
                key: parse_json(&key)?,
                aggregate_sequence: sequence as u64,
                state: OutboxState::Pending,
            });
        }
        collected
    };

    Ok(RecoveryView {
        generation,
        daemon,
        launch_intents,
        owned_processes,
        leases,
        attempts,
        dispatches,
        adapter_sessions,
        audit_head: audit_runtime::current_head(connection)?,
        pending_outbox,
    })
}

fn dispatch_view(
    connection: &Connection,
    dispatch_id: &DispatchId,
) -> Result<DispatchView, StateError> {
    type DispatchRow = (
        String,
        String,
        i64,
        String,
        String,
        Option<String>,
        Option<String>,
    );
    let row: Option<DispatchRow> = connection
        .query_row(
            "SELECT dispatch_id, attempt_id, ordinal, binding_kind, state, session_id,
                        intent_state
                 FROM dispatches WHERE dispatch_id = ?1",
            params![dispatch_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    let Some((dispatch, attempt, ordinal, binding, state, session, intent)) = row else {
        return Err(StateError::NotFound {
            target: StateTarget::Dispatch(dispatch_id.clone()),
        });
    };
    Ok(DispatchView {
        record: DispatchRecord {
            dispatch_id: DispatchId::new(dispatch).map_err(|_| decode_error())?,
            attempt_id: AttemptId::new(attempt).map_err(|_| decode_error())?,
            ordinal: DispatchOrdinal(ordinal as u32),
            binding_kind: parse_json(&binding)?,
            state: parse_json(&state)?,
            session_id: session
                .as_deref()
                .map(|value| SessionId::new(value).map_err(|_| decode_error()))
                .transpose()?,
        },
        intent: intent.as_deref().map(parse_json).transpose()?,
        session: session
            .map(|value| SessionId::new(value).map_err(|_| decode_error()))
            .transpose()?,
    })
}

fn attempt_view(
    connection: &Connection,
    attempt_id: &AttemptId,
) -> Result<AttemptView, StateError> {
    let row: Option<(String, i64, Option<String>)> = connection
        .query_row(
            "SELECT state, retry_count, active_dispatch_id FROM attempts WHERE attempt_id = ?1",
            params![attempt_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((state, retry, active)) = row else {
        return Err(StateError::NotFound {
            target: StateTarget::Attempt(attempt_id.clone()),
        });
    };
    Ok(AttemptView {
        record: AttemptRecord {
            attempt_id: attempt_id.clone(),
            state: parse_json(&state)?,
            retry_count: retry.clamp(0, 255) as u8,
        },
        active_dispatch: active
            .map(|value| DispatchId::new(value).map_err(|_| decode_error()))
            .transpose()?,
    })
}

fn readiness_verdict(
    connection: &Connection,
    certificate_id: &CertificateId,
    input_fingerprint: FingerprintDigest,
) -> Result<CertificateVerdict, StateError> {
    let matching: Option<(String, Option<String>)> = connection
        .query_row(
            "SELECT verdict, reason FROM readiness_certificates
             WHERE certificate_id = ?1 AND input_fingerprint = ?2",
            params![certificate_id.as_str(), input_fingerprint.0.to_hex()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db_error)?;
    if let Some((verdict, reason)) = matching {
        if verdict == "current" {
            return Ok(CertificateVerdict::Current {
                certificate_id: certificate_id.clone(),
                input_fingerprint,
            });
        }
        let reason: CertificateInvalidReason = reason
            .as_deref()
            .map(parse_json)
            .transpose()?
            .unwrap_or(CertificateInvalidReason::CheckNotCurrent);
        return Ok(CertificateVerdict::Invalid { reason });
    }
    let issued: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM readiness_certificates WHERE certificate_id = ?1 LIMIT 1",
            params![certificate_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    if issued.is_some() {
        Ok(CertificateVerdict::Invalid {
            reason: CertificateInvalidReason::StaleFingerprint,
        })
    } else {
        Ok(CertificateVerdict::Absent {
            reason: CertificateAbsentReason::NotIssued,
        })
    }
}

fn outbox_view(connection: &Connection, outbox_id: &OutboxId) -> Result<OutboxView, StateError> {
    type OutboxRow = (String, String, i64, String, String, Option<i64>, String);
    let row: Option<OutboxRow> = connection
        .query_row(
            "SELECT outbox_id, destination, aggregate_sequence, outbox_key, payload_digest,
                    last_observed_at_ms, state
             FROM outbox WHERE outbox_id = ?1",
            params![outbox_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    let Some((id, destination, sequence, key, digest, observed, stored_state)) = row else {
        return Err(StateError::NotFound {
            target: StateTarget::Outbox(outbox_id.clone()),
        });
    };
    Ok(OutboxView {
        intent: OutboxIntent {
            outbox_id: OutboxId::new(id).map_err(|_| decode_error())?,
            destination: parse_json(&destination)?,
            key: parse_json(&key)?,
            aggregate_sequence: sequence as u64,
            payload_digest: Sha256Digest::from_hex(&digest).map_err(|_| decode_error())?,
            state: parse_json(&stored_state)?,
        },
        last_observed_at: observed.map(UtcMillis),
    })
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Local mirror of `SafeArtifactRef` used only for the persisted JSON column;
/// the record itself does not derive `Serialize`.
#[derive(serde::Serialize, serde::Deserialize)]
struct ArtifactJson {
    relative_path: String,
    digest: String,
    bytes: u64,
}

impl From<&SafeArtifactRef> for ArtifactJson {
    fn from(artifact: &SafeArtifactRef) -> Self {
        Self {
            relative_path: artifact.relative_path.as_str().to_string(),
            digest: artifact.digest.to_string(),
            bytes: artifact.bytes,
        }
    }
}

fn json<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, StateError> {
    serde_json::to_string(value).map_err(|_| StateError::Encode { field: "state" })
}

fn parse_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, StateError> {
    serde_json::from_str(text).map_err(|_| decode_error())
}

fn parse_lease_scope(text: &str) -> Result<LeaseScope, StateError> {
    let value: serde_json::Value = parse_json(text)?;
    match value.get("kind").and_then(|kind| kind.as_str()) {
        Some("scratch" | "scratch_directory") => Ok(LeaseScope::ScratchDirectory(
            WindowsAbsolutePath::new(
                value
                    .get("path")
                    .and_then(|path| path.as_str())
                    .ok_or_else(decode_error)?,
            )
            .map_err(|_| decode_error())?,
        )),
        Some("repository") => Ok(LeaseScope::Repository {
            worktree: WindowsAbsolutePath::new(
                value
                    .get("worktree")
                    .and_then(|path| path.as_str())
                    .ok_or_else(decode_error)?,
            )
            .map_err(|_| decode_error())?,
            branch: BranchName::new(
                value
                    .get("branch")
                    .and_then(|branch| branch.as_str())
                    .ok_or_else(decode_error)?,
            )
            .map_err(|_| decode_error())?,
            base_sha: GitSha::from_hex(
                value
                    .get("base_sha")
                    .and_then(|sha| sha.as_str())
                    .ok_or_else(decode_error)?,
            )
            .map_err(|_| decode_error())?,
        }),
        _ => Err(decode_error()),
    }
}

fn parse_lease_kind(text: &str) -> Result<LeaseKind, StateError> {
    match text {
        "\"scratch\"" => Ok(LeaseKind::Scratch),
        "\"implementation\"" => Ok(LeaseKind::Implementation),
        _ => Err(decode_error()),
    }
}

fn parse_lease_state(text: &str) -> Result<LeaseState, StateError> {
    match text {
        "\"reserved\"" => Ok(LeaseState::Reserved),
        "\"active\"" => Ok(LeaseState::Active),
        "\"recovery_held\"" => Ok(LeaseState::RecoveryHeld),
        "\"retired\"" => Ok(LeaseState::Retired),
        _ => Err(decode_error()),
    }
}

fn source_label(source: super::contracts::adapter::InboxSource) -> &'static str {
    match source {
        super::contracts::adapter::InboxSource::Trello => "trello",
    }
}

fn attempt_label(state: AttemptState) -> &'static str {
    match state {
        AttemptState::Reserved => "reserved",
        AttemptState::LaunchIntent => "launch_intent",
        AttemptState::Running => "running",
        AttemptState::Verifying => "verifying",
        AttemptState::Reviewing => "reviewing",
        AttemptState::Succeeded => "succeeded",
        AttemptState::Failed => "failed",
        AttemptState::CancelPending => "cancel_pending",
        AttemptState::Cancelled => "cancelled",
        AttemptState::RecoveryRequired => "recovery_required",
    }
}

fn dispatch_label(state: DispatchState) -> &'static str {
    match state {
        DispatchState::Reserved => "reserved",
        DispatchState::LaunchIntent => "launch_intent",
        DispatchState::Running => "running",
        DispatchState::Cancelling => "cancelling",
        DispatchState::Cancelled => "cancelled",
        DispatchState::Succeeded => "succeeded",
        DispatchState::Failed => "failed",
        DispatchState::RecoveryRequired => "recovery_required",
    }
}

fn task_label(state: TaskState) -> &'static str {
    match state {
        TaskState::Planned => "planned",
        TaskState::Ready => "ready",
        TaskState::Running => "running",
        TaskState::Verifying => "verifying",
        TaskState::Reviewing => "reviewing",
        TaskState::RepairPending => "repair_pending",
        TaskState::VerifiedHandoff => "verified_handoff",
        TaskState::Integrating => "integrating",
        TaskState::Blocked => "blocked",
        TaskState::RecoveryRequired => "recovery_required",
        TaskState::IntegratedClosed => "integrated_closed",
        TaskState::Withdrawn => "withdrawn",
        TaskState::Cancelled => "cancelled",
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn now_ms() -> UtcMillis {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0);
    UtcMillis(millis)
}

fn internal(code: InternalErrorCode) -> StateError {
    StateError::Internal { code }
}

fn db_error(_: rusqlite::Error) -> StateError {
    internal(InternalErrorCode::Io)
}

fn decode_error() -> StateError {
    internal(InternalErrorCode::Decode)
}

fn map_constraint(error: rusqlite::Error, constraint: &'static str) -> StateError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            StateError::ConstraintViolation { constraint }
        }
        other => db_error(other),
    }
}

// ---------------------------------------------------------------------------
// Unit tests for channel discipline and the writer's failure mode
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::audit::{
        AuditAction, AuditActor, AuditEventDraft, AuditOperation, AuditOutcome, AuditReason,
        AuditScope,
    };
    use crate::contracts::primitives::SafeCode;
    use crate::contracts::state::request_id;

    fn draft(name: &str) -> AuditEventDraft {
        AuditEventDraft {
            schema_version: 1,
            actor: AuditActor::Supervisor {
                generation: DaemonGeneration(1),
            },
            action: AuditAction::Denial {
                operation: AuditOperation(SafeCode::new("writer_test").expect("operation")),
                reason: AuditReason(SafeCode::new(name).expect("reason")),
            },
            scope: AuditScope::Daemon {
                generation: DaemonGeneration(1),
            },
            policy_refs: Vec::new(),
            evidence_refs: Vec::new(),
            outcome: AuditOutcome::Recorded,
            recorded_at_ms: UtcMillis(0),
        }
    }

    fn txn(name: &str) -> StateTxn {
        StateTxn::new(
            request_id(name).expect("request"),
            DaemonGeneration(1),
            UtcMillis(0),
            Vec::new(),
            vec![draft(name)],
            Vec::new(),
        )
        .expect("valid txn")
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    }

    #[test]
    fn bounded_channel_times_out_without_committing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SqliteStateStore::open(dir.path().join("state.db")).expect("open");
        let runtime = runtime();

        // Park the writer so the bounded queue fills behind it.
        let (ready_tx, ready_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        store
            .channel()
            .expect("channel")
            .try_send(Command::Hold {
                ready: ready_tx,
                release: release_rx,
            })
            .expect("hold");
        runtime.block_on(ready_rx).expect("writer parked");

        for index in 0..STATE_CHANNEL_CAPACITY {
            let (reply, _response) = oneshot::channel();
            store
                .channel()
                .expect("channel")
                .try_send(Command::Commit {
                    txn: txn(&format!("queued_{index}")),
                    reply,
                })
                .expect("queue slot");
        }

        let started = std::time::Instant::now();
        let error = runtime
            .block_on(store.submit(txn("overflow")))
            .expect_err("saturated");
        assert!(matches!(
            error,
            StateError::Backpressure {
                capacity: STATE_CHANNEL_CAPACITY
            }
        ));
        assert!(
            started.elapsed() >= STATE_SUBMIT_TIMEOUT,
            "a submit timeout is measured against the 5 s D4 bound"
        );

        release_tx.send(()).expect("release writer");

        // A timeout is not a commit: the queued envelopes failed generation
        // validation, and the overflow request never entered the channel.
        match runtime
            .block_on(store.query(StateQuery::AuditHead))
            .expect("head")
        {
            StateReply::AuditHead(head) => assert_eq!(head.sequence.get(), 0),
            other => panic!("unexpected reply: {other:?}"),
        }
        store.close().expect("close");
    }

    #[test]
    fn writer_panic_never_fabricates_a_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SqliteStateStore::open(dir.path().join("state.db")).expect("open");
        let runtime = runtime();

        let begin = StateTxn::new(
            request_id("begin").expect("request"),
            DaemonGeneration(1),
            UtcMillis(0),
            vec![StateMutation {
                target: StateTarget::DaemonGeneration,
                expected_revision: None,
                op: StateOp::BeginDaemonGeneration {
                    started_at_ms: UtcMillis(0),
                },
            }],
            Vec::new(),
            Vec::new(),
        )
        .expect("valid begin");
        runtime
            .block_on(store.submit(begin))
            .expect("commit before crash");
        runtime
            .block_on(store.crash_writer())
            .expect("crash injected");

        let mut saw_unavailable = false;
        for _ in 0..200 {
            match runtime.block_on(store.submit(txn("after_crash"))) {
                Err(StateError::WriterUnavailable) => {
                    saw_unavailable = true;
                    break;
                }
                Err(_) | Ok(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        assert!(
            saw_unavailable,
            "closed writer must surface WriterUnavailable"
        );
        assert!(matches!(
            runtime.block_on(store.query(StateQuery::AuditHead)),
            Err(StateError::WriterUnavailable)
        ));
    }
}
