-- Vestry schema v1 (C7, 43 tables). `schema_migrations` is created by the
-- migration runner before this train applies; the 42 statements below build
-- the remaining tables in C7 design order, which is FK-topological.
-- Canonical LF bytes; checksums cover these exact bytes (C7 rule 2).

CREATE TABLE daemon_generations (
    generation INTEGER PRIMARY KEY,
    started_at_ms INTEGER NOT NULL,
    clean_shutdown INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE goals (
    goal_id TEXT PRIMARY KEY,
    project_id TEXT REFERENCES projects(project_id),
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE clarification_requests (
    clarification_id TEXT PRIMARY KEY,
    goal_id TEXT REFERENCES goals(goal_id),
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE issue_budgets (
    goal_id TEXT PRIMARY KEY REFERENCES goals(goal_id),
    limit_value INTEGER NOT NULL,
    used_value INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL
);

CREATE TABLE repair_cycles (
    repair_cycle_id TEXT PRIMARY KEY,
    goal_id TEXT REFERENCES goals(goal_id),
    attempt INTEGER NOT NULL,
    state TEXT NOT NULL
);

CREATE TABLE watchdog_episodes (
    watchdog_episode_id TEXT PRIMARY KEY,
    generation INTEGER REFERENCES daemon_generations(generation),
    reason TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER
);

CREATE TABLE anchors (
    anchor_id TEXT PRIMARY KEY,
    goal_id TEXT REFERENCES goals(goal_id),
    anchor_sha TEXT NOT NULL,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE criterion_defs (
    criterion_id TEXT PRIMARY KEY,
    text TEXT NOT NULL
);

CREATE TABLE anchor_criteria (
    anchor_id TEXT NOT NULL REFERENCES anchors(anchor_id),
    criterion_id TEXT NOT NULL REFERENCES criterion_defs(criterion_id),
    PRIMARY KEY (anchor_id, criterion_id)
);

CREATE TABLE charter_amendments (
    amendment_id TEXT PRIMARY KEY,
    anchor_id TEXT REFERENCES anchors(anchor_id),
    body TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE gate_artefacts (
    artefact_id TEXT PRIMARY KEY,
    gate INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    artefact_digest TEXT NOT NULL
);

CREATE TABLE gate_decisions (
    gate_decision_id TEXT PRIMARY KEY,
    artefact_id TEXT REFERENCES gate_artefacts(artefact_id),
    decision TEXT NOT NULL,
    decided_at_ms INTEGER NOT NULL
);

CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    goal_id TEXT REFERENCES goals(goal_id),
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE task_edges (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    depends_on_task_id TEXT NOT NULL REFERENCES tasks(task_id),
    PRIMARY KEY (task_id, depends_on_task_id)
);

CREATE TABLE task_criteria (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    criterion_id TEXT NOT NULL REFERENCES criterion_defs(criterion_id),
    PRIMARY KEY (task_id, criterion_id)
);

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    goal_id TEXT REFERENCES goals(goal_id),
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY,
    run_id TEXT REFERENCES runs(run_id),
    state TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    active_dispatch_id TEXT,
    recovery_reason TEXT,
    recovery_finding_id TEXT,
    revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY,
    attempt_id TEXT REFERENCES attempts(attempt_id),
    kind TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    generation INTEGER NOT NULL,
    fence INTEGER NOT NULL,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE invocation_admissions (
    admission_id TEXT PRIMARY KEY,
    attempt_id TEXT REFERENCES attempts(attempt_id),
    manifest_id TEXT,
    canary_id TEXT,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE dispatches (
    dispatch_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    ordinal INTEGER NOT NULL,
    binding_kind TEXT NOT NULL,
    state TEXT NOT NULL,
    session_id TEXT,
    admission_id TEXT,
    manifest_id TEXT,
    canary_id TEXT,
    lease_id TEXT,
    fence INTEGER,
    intent_state TEXT,
    created_at_ms INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    UNIQUE (attempt_id, ordinal)
);

CREATE TABLE owned_processes (
    process_record_id TEXT PRIMARY KEY,
    dispatch_id TEXT REFERENCES dispatches(dispatch_id),
    identity_pid INTEGER,
    identity_creation_filetime INTEGER,
    executable_digest TEXT NOT NULL,
    job_generation INTEGER NOT NULL,
    observed_state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    UNIQUE (dispatch_id)
);

CREATE TABLE policies (
    policy_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    digest TEXT NOT NULL,
    body_json TEXT NOT NULL
);

CREATE TABLE action_requests (
    action_id TEXT PRIMARY KEY,
    goal_id TEXT REFERENCES goals(goal_id),
    operation TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    action_id TEXT REFERENCES action_requests(action_id),
    state TEXT NOT NULL,
    expires_at_ms INTEGER,
    consumed_at_ms INTEGER,
    revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE effect_intents (
    effect_id TEXT PRIMARY KEY,
    action_id TEXT REFERENCES action_requests(action_id),
    intent_key TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE readiness_certificates (
    certificate_id TEXT NOT NULL,
    input_fingerprint TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reason TEXT,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (certificate_id, input_fingerprint)
);

CREATE TABLE check_manifests (
    check_manifest_id TEXT PRIMARY KEY,
    goal_id TEXT REFERENCES goals(goal_id),
    manifest_digest TEXT NOT NULL
);

CREATE TABLE check_results (
    check_result_id TEXT PRIMARY KEY,
    check_manifest_id TEXT REFERENCES check_manifests(check_manifest_id),
    status TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE reviews (
    review_id TEXT PRIMARY KEY,
    goal_id TEXT REFERENCES goals(goal_id),
    candidate_sha TEXT NOT NULL,
    state TEXT NOT NULL
);

CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    artefact TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    producer TEXT NOT NULL,
    revision INTEGER NOT NULL,
    redaction_version INTEGER NOT NULL,
    integrity TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE object_criteria (
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL REFERENCES criterion_defs(criterion_id),
    PRIMARY KEY (object_kind, object_id, criterion_id)
);

CREATE TABLE usage_steps (
    usage_step_id TEXT PRIMARY KEY,
    attempt_id TEXT REFERENCES attempts(attempt_id),
    step_key TEXT NOT NULL,
    counters_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE trello_mappings (
    mapping_id TEXT PRIMARY KEY,
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    board_id TEXT NOT NULL,
    list_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    UNIQUE (object_kind, object_id)
);

CREATE TABLE outbox (
    outbox_id TEXT PRIMARY KEY,
    destination TEXT NOT NULL,
    outbox_key TEXT NOT NULL,
    aggregate_sequence INTEGER NOT NULL,
    payload_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    last_observed_at_ms INTEGER,
    UNIQUE (destination, outbox_key)
);

CREATE TABLE inbox (
    inbox_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    inbox_key TEXT NOT NULL,
    digest TEXT NOT NULL,
    aggregate_sequence INTEGER NOT NULL,
    received_at_ms INTEGER NOT NULL,
    UNIQUE (source, inbox_key)
);

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    schema_version INTEGER NOT NULL,
    draft_json TEXT NOT NULL,
    canonical_bytes BLOB NOT NULL,
    recorded_at_ms INTEGER NOT NULL
);

CREATE TABLE attention (
    attention_id TEXT PRIMARY KEY,
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE memory_facts (
    memory_fact_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    fact_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE adapter_stores (
    store_id TEXT PRIMARY KEY,
    attempt_id TEXT REFERENCES attempts(attempt_id),
    absolute_identity TEXT NOT NULL,
    session_id TEXT,
    export_state TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE capability_manifests (
    manifest_id TEXT PRIMARY KEY,
    adapter_id TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    qualified_at_ms INTEGER NOT NULL
);

CREATE TABLE canary_results (
    canary_id TEXT PRIMARY KEY,
    adapter_id TEXT NOT NULL,
    result TEXT NOT NULL,
    evidence_id TEXT REFERENCES evidence(evidence_id),
    created_at_ms INTEGER NOT NULL
);
