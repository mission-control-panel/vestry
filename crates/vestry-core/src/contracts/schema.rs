//! C7 schema versioning and migration ownership. Exactly 43 tables.

use serde::{Deserialize, Serialize};

pub const CURRENT_SCHEMA_VERSION: SchemaVersion = SchemaVersion(1);
pub const EXPECTED_TABLE_COUNT: usize = 43;

/// The 43 table names in LLD §3 design order.
pub const TABLE_NAMES: [&str; EXPECTED_TABLE_COUNT] = [
    "schema_migrations",
    "daemon_generations",
    "projects",
    "goals",
    "clarification_requests",
    "issue_budgets",
    "repair_cycles",
    "watchdog_episodes",
    "anchors",
    "criterion_defs",
    "anchor_criteria",
    "charter_amendments",
    "gate_artefacts",
    "gate_decisions",
    "tasks",
    "task_edges",
    "task_criteria",
    "runs",
    "attempts",
    "leases",
    "invocation_admissions",
    "dispatches",
    "owned_processes",
    "policies",
    "action_requests",
    "approvals",
    "effect_intents",
    "readiness_certificates",
    "check_manifests",
    "check_results",
    "reviews",
    "evidence",
    "object_criteria",
    "usage_steps",
    "trello_mappings",
    "outbox",
    "inbox",
    "audit_events",
    "attention",
    "memory_facts",
    "adapter_stores",
    "capability_manifests",
    "canary_results",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaVersion(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MigrationId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MigrationChecksum(pub super::primitives::Sha256Digest);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRecord {
    pub version: MigrationId,
    pub checksum: MigrationChecksum,
    pub applied_at_ms: super::primitives::UtcMillis,
    pub binary_revision: BinaryRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BinaryRevision(pub super::primitives::SafeText);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaCompatibility {
    Current,
    MigrationRequired {
        from: SchemaVersion,
        to: SchemaVersion,
    },
    /// Unknown/newer fails closed: no write, no downgrade, no erase.
    UnsupportedNewer {
        found: SchemaVersion,
        supported: SchemaVersion,
    },
    ChecksumMismatch {
        version: MigrationId,
    },
    MissingMigration {
        version: MigrationId,
    },
    Unreadable {
        reason: SchemaReadError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaReadError {
    DatabaseMissing,
    OpenFailed,
    IntegrityCheckFailed,
    ForeignKeyCheckFailed,
    MigrationTableMalformed,
}

impl SchemaCompatibility {
    pub fn permits_write_startup(&self) -> bool {
        matches!(self, Self::Current)
    }
}

/// Closed internal error codes; never a free-form string (C4 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalErrorCode {
    Panic,
    ChannelClosed,
    Encode,
    Decode,
    Invariant,
    Io,
}
