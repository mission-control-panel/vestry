//! Runtime audit persistence (LLD §9). Track 1 owns this subtree (T41 §6.3).
//!
//! The byte rules and the encoder are frozen in `contracts::audit`; this
//! module only stores, reads and verifies events through that encoder. It
//! never re-implements canonicalization. Rows are append-only: the writer
//! thread inserts inside the same `BEGIN IMMEDIATE` transaction as state and
//! outbox, and nothing here updates or deletes an existing event.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use super::contracts::audit::{
    canonical_bytes, compute_event_hash, verify_chain, AuditEvent, AuditEventDraft, AuditHead,
    ChainVerdict,
};
use super::contracts::primitives::{AuditSequence, Hash32, UtcMillis};
use super::contracts::schema::InternalErrorCode;
use super::contracts::state::StateError;

fn db_error(_: rusqlite::Error) -> StateError {
    StateError::Internal {
        code: InternalErrorCode::Io,
    }
}

fn decode_error() -> StateError {
    StateError::Internal {
        code: InternalErrorCode::Decode,
    }
}

/// Result of appending the drafts carried by one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditAppend {
    /// Sequence of the last appended event, present iff at least one was added.
    pub last_sequence: Option<AuditSequence>,
    pub head: AuditHead,
}

/// The current trusted head from `audit_events`; an empty chain is sequence 0
/// with the all-zero hash (genesis previous hash is checked on append).
pub(crate) fn current_head(conn: &Connection) -> Result<AuditHead, StateError> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db_error)?;
    match row {
        None => Ok(AuditHead {
            sequence: AuditSequence(0),
            hash: Hash32::ZERO,
        }),
        Some((sequence, hash)) => Ok(AuditHead {
            sequence: AuditSequence(sequence as u64),
            hash: Hash32::from_hex(&hash).map_err(|_| decode_error())?,
        }),
    }
}

/// Appends drafts in order, assigning contiguous sequences and the previous
/// hash from `head`. Any canonicalization failure aborts the whole call (the
/// caller's transaction then rolls back).
pub(crate) fn append(
    tx: &Transaction<'_>,
    drafts: &[AuditEventDraft],
    mut head: AuditHead,
    committed_at_ms: UtcMillis,
) -> Result<AuditAppend, StateError> {
    let mut last_sequence = None;
    for draft in drafts {
        let sequence = head.sequence.next();
        let mut event = AuditEvent {
            sequence,
            previous_hash: head.hash,
            schema_version: draft.schema_version,
            actor: draft.actor.clone(),
            action: draft.action.clone(),
            scope: draft.scope.clone(),
            policy_refs: draft.policy_refs.clone(),
            evidence_refs: draft.evidence_refs.clone(),
            outcome: draft.outcome.clone(),
            recorded_at_ms: draft.recorded_at_ms,
            event_hash: Hash32::ZERO,
        };
        let hash = compute_event_hash(&event).map_err(|_| StateError::Encode {
            field: "audit_event",
        })?;
        event.event_hash = hash;
        let bytes = canonical_bytes(&event).map_err(|_| StateError::Encode {
            field: "audit_event",
        })?;
        let draft_json = serde_json::to_string(draft).map_err(|_| StateError::Encode {
            field: "audit_event",
        })?;
        tx.execute(
            "INSERT INTO audit_events
                 (sequence, previous_hash, event_hash, schema_version, draft_json,
                  canonical_bytes, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                sequence.get() as i64,
                head.hash.to_hex(),
                hash.to_hex(),
                event.schema_version as i64,
                draft_json,
                bytes,
                committed_at_ms.0,
            ],
        )
        .map_err(db_error)?;
        head = AuditHead { sequence, hash };
        last_sequence = Some(sequence);
    }
    Ok(AuditAppend {
        last_sequence,
        head,
    })
}

/// Reads the stored chain in sequence order, reconstructing each event from
/// its draft JSON plus the chain columns. Used for verification and tests.
pub(crate) fn read_events(conn: &Connection) -> Result<Vec<AuditEvent>, StateError> {
    let mut statement = conn
        .prepare(
            "SELECT sequence, previous_hash, event_hash, draft_json
             FROM audit_events ORDER BY sequence ASC",
        )
        .map_err(db_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(db_error)?;
    let mut events = Vec::new();
    for row in rows {
        let (sequence, previous_hash, event_hash, draft_json) = row.map_err(db_error)?;
        let draft: AuditEventDraft =
            serde_json::from_str(&draft_json).map_err(|_| decode_error())?;
        events.push(AuditEvent {
            sequence: AuditSequence(sequence as u64),
            previous_hash: Hash32::from_hex(&previous_hash).map_err(|_| decode_error())?,
            schema_version: draft.schema_version,
            actor: draft.actor,
            action: draft.action,
            scope: draft.scope,
            policy_refs: draft.policy_refs,
            evidence_refs: draft.evidence_refs,
            outcome: draft.outcome,
            recorded_at_ms: draft.recorded_at_ms,
            event_hash: Hash32::from_hex(&event_hash).map_err(|_| decode_error())?,
        });
    }
    Ok(events)
}

/// Verifies the persisted chain and that its head equals the stored head.
pub(crate) fn verify_persisted(conn: &Connection) -> Result<ChainVerdict, StateError> {
    let events = read_events(conn)?;
    let head = current_head(conn)?;
    Ok(verify_chain(
        &events,
        if head.sequence.get() == 0 {
            None
        } else {
            Some(head)
        },
    ))
}
