//! C5 golden vectors A/B/C and canonical negative cases (model-free).
//!
//! Vector bytes are hardcoded expectations from the frozen design; the encoder
//! must reproduce them exactly, with no trailing newline.

use vestry_core::contracts::adapter::Role;
use vestry_core::contracts::audit::{
    canonical_bytes, canonicalize_json_bytes, compute_event_hash, encode_canon, verify_chain,
    AnchoredInvocationScope, AuditAction, AuditActor, AuditEvent, AuditGateRef, AuditOperation,
    AuditOutcome, AuditReason, AuditScope, Canon, CanonicalError, ChainVerdict, PolicyRef,
    PreAnchorDiscoveryScope, StateCode, AUDIT_DOMAIN_V1,
};
use vestry_core::contracts::primitives::{
    AdmissionId, AnchorId, AttemptId, AuditSequence, CertificateId, CriterionId, DaemonGeneration,
    DispatchId, DispatchOrdinal, EvidenceId, Fence, GitSha, GoalId, Hash32, LeaseId,
    PolicyRevision, Revision, SafeCode, ScratchScope, Sha256Digest, TaskId, UtcMillis,
};

const VECTOR_A: &str = r#"{"action":{"kind":"denial","operation":"discovery_preflight","reason":"canary_unverified"},"actor":{"generation":7,"kind":"supervisor"},"evidence_refs":[],"outcome":{"kind":"denied"},"policy_refs":["policy:7"],"previous_hash":"0000000000000000000000000000000000000000000000000000000000000000","recorded_at_ms":1763100000000,"schema_version":1,"scope":{"admission_id":"adm_01","attempt_id":"att_01","dispatch_ordinal":1,"fence":9,"goal_id":"goal_01","intake_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","intake_revision":2,"kind":"pre_anchor_discovery","role":"discovery","scratch_scope":"scratch/goal_01","target_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"},"sequence":1}"#;

const VECTOR_B: &str = r#"{"action":{"from":"running","kind":"state_transition","to":"cancel_pending"},"actor":{"generation":7,"kind":"supervisor"},"evidence_refs":["ev_01"],"outcome":{"kind":"succeeded"},"policy_refs":["policy:7"],"previous_hash":"b72c9a1f741f80265d60778b00eb68c379e138a60a0860cfdbf901bfa9d73822","recorded_at_ms":1763100000123,"schema_version":1,"scope":{"admission_id":"adm_01","anchor_id":"anc_01","attempt_id":"att_01","base_sha":"git:abababababababababababababababababababab","certificate_ref":"cert_01","criterion_ids":["crit_01","crit_02"],"dispatch_id":"dsp_01","dispatch_ordinal":1,"fence":9,"gate_refs":["gate:1:rev7","gate:2:rev7","gate:3:plan1"],"goal_id":"goal_01","kind":"anchored_invocation","lease_id":"lease_01","role":"worker","task_id":"task_01","task_revision":3},"sequence":2}"#;

const VECTOR_C: &str = r#"{"action":{"kind":"denial","operation":"discovery_preflight","reason":"malformed_policy"},"actor":{"generation":7,"kind":"supervisor"},"evidence_refs":[],"outcome":{"kind":"denied"},"policy_refs":["policy:7"],"previous_hash":"02672c6da7fd439af645df5f73d3252a97f3a49c2088681c60882ced01ad1650","recorded_at_ms":1763100000456,"schema_version":1,"scope":{"admission_id":"adm_02","attempt_id":"att_02","dispatch_ordinal":2,"fence":10,"goal_id":"goal_01","intake_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","intake_revision":2,"kind":"pre_anchor_discovery","role":"discovery","scratch_scope":"C:\\Users\\测试\\vestry \"quoted\" path","target_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"},"sequence":3}"#;

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

fn discovery_scope(
    admission: &str,
    attempt: &str,
    ordinal: u32,
    fence: u64,
    scratch: &str,
) -> AuditScope {
    AuditScope::PreAnchorDiscovery(PreAnchorDiscoveryScope {
        goal_id: GoalId::new("goal_01").unwrap(),
        intake_digest: Sha256Digest::from_hex(&"1".repeat(64)).unwrap(),
        intake_revision: Revision(2),
        target_digest: Sha256Digest::from_hex(&"2".repeat(64)).unwrap(),
        scratch_scope: ScratchScope::new(scratch).unwrap(),
        role: Role::Discovery,
        admission_id: AdmissionId::new(admission).unwrap(),
        attempt_id: AttemptId::new(attempt).unwrap(),
        dispatch_ordinal: DispatchOrdinal(ordinal),
        fence: Fence(fence),
    })
}

fn event(
    sequence: u64,
    previous: &str,
    action: AuditAction,
    scope: AuditScope,
    evidence: Vec<EvidenceId>,
    recorded_at_ms: i64,
) -> AuditEvent {
    AuditEvent {
        sequence: AuditSequence(sequence),
        previous_hash: Hash32::from_hex(previous).unwrap(),
        schema_version: 1,
        actor: actor(),
        action,
        scope,
        policy_refs: policy(),
        evidence_refs: evidence,
        outcome: AuditOutcome::Denied,
        recorded_at_ms: UtcMillis(recorded_at_ms),
        event_hash: Hash32::ZERO,
    }
}

fn vector_a() -> AuditEvent {
    event(
        1,
        &"0".repeat(64),
        AuditAction::Denial {
            operation: AuditOperation(SafeCode::new("discovery_preflight").unwrap()),
            reason: AuditReason(SafeCode::new("canary_unverified").unwrap()),
        },
        discovery_scope("adm_01", "att_01", 1, 9, "scratch/goal_01"),
        Vec::new(),
        1_763_100_000_000,
    )
}

fn vector_b() -> AuditEvent {
    let mut value = event(
        2,
        HASH_A,
        AuditAction::StateTransition {
            from: StateCode::Running,
            to: StateCode::CancelPending,
        },
        AuditScope::AnchoredInvocation(AnchoredInvocationScope {
            goal_id: GoalId::new("goal_01").unwrap(),
            anchor_id: AnchorId::new("anc_01").unwrap(),
            criterion_ids: vec![
                CriterionId::new("crit_01").unwrap(),
                CriterionId::new("crit_02").unwrap(),
            ],
            admission_id: AdmissionId::new("adm_01").unwrap(),
            attempt_id: AttemptId::new("att_01").unwrap(),
            dispatch_ordinal: DispatchOrdinal(1),
            fence: Fence(9),
            role: Role::Worker,
            base_sha: GitSha::from_hex(&"ab".repeat(20)).unwrap(),
            certificate_ref: Some(CertificateId::new("cert_01").unwrap()),
            gate_refs: vec![
                AuditGateRef(SafeCode::new("gate:1:rev7").unwrap()),
                AuditGateRef(SafeCode::new("gate:2:rev7").unwrap()),
                AuditGateRef(SafeCode::new("gate:3:plan1").unwrap()),
            ],
            task_id: Some(TaskId::new("task_01").unwrap()),
            task_revision: Some(Revision(3)),
            lease_id: Some(LeaseId::new("lease_01").unwrap()),
            dispatch_id: Some(DispatchId::new("dsp_01").unwrap()),
        }),
        vec![EvidenceId::new("ev_01").unwrap()],
        1_763_100_000_123,
    );
    value.outcome = AuditOutcome::Succeeded;
    value
}

fn vector_c() -> AuditEvent {
    event(
        3,
        HASH_B,
        AuditAction::Denial {
            operation: AuditOperation(SafeCode::new("discovery_preflight").unwrap()),
            reason: AuditReason(SafeCode::new("malformed_policy").unwrap()),
        },
        discovery_scope(
            "adm_02",
            "att_02",
            2,
            10,
            "C:\\Users\\测试\\vestry \"quoted\" path",
        ),
        Vec::new(),
        1_763_100_000_456,
    )
}

#[test]
fn audit_vectors_a_b_c_are_byte_exact() {
    for (built, expected, expected_hash, expected_len) in [
        (vector_a(), VECTOR_A, HASH_A, 746usize),
        (vector_b(), VECTOR_B, HASH_B, 789usize),
        (vector_c(), VECTOR_C, HASH_C, 772usize),
    ] {
        let bytes = canonical_bytes(&built).expect("canonical encoding");
        assert_eq!(
            std::str::from_utf8(&bytes).expect("utf-8"),
            expected,
            "canonical bytes"
        );
        assert_eq!(bytes.len(), expected_len, "byte length");
        assert!(!bytes.ends_with(b"\n"), "no trailing newline");
        let hash = compute_event_hash(&built).expect("hash");
        assert_eq!(hash.to_hex(), expected_hash, "event hash");
    }
}

#[test]
fn audit_vectors_chain() {
    let mut a = vector_a();
    a.event_hash = compute_event_hash(&a).unwrap();
    let mut b = vector_b();
    b.event_hash = compute_event_hash(&b).unwrap();
    let mut c = vector_c();
    c.event_hash = compute_event_hash(&c).unwrap();

    let head = vestry_core::contracts::audit::AuditHead {
        sequence: c.sequence,
        hash: c.event_hash,
    };
    assert_eq!(
        verify_chain(&[a.clone(), b.clone(), c.clone()], Some(head)),
        ChainVerdict::Valid { head }
    );

    // One-bit tamper of event B breaks its own hash.
    let mut tampered = b.clone();
    tampered.recorded_at_ms = UtcMillis(tampered.recorded_at_ms.0 + 1);
    assert!(matches!(
        verify_chain(&[a.clone(), tampered, c.clone()], Some(head)),
        ChainVerdict::EventHashMismatch { .. }
    ));

    // A trusted head that differs is never silently accepted.
    let wrong_head = vestry_core::contracts::audit::AuditHead {
        sequence: head.sequence,
        hash: Hash32::ZERO,
    };
    assert!(matches!(
        verify_chain(&[a, b, c], Some(wrong_head)),
        ChainVerdict::HeadMismatch { .. }
    ));
}

#[test]
fn audit_domain_separation_changes_digest() {
    let event = vector_a();
    let bytes = canonical_bytes(&event).unwrap();
    let ours = compute_event_hash(&event).unwrap();
    let other = vestry_core::contracts::audit::domain_digest(b"vestry.audit.event.v2", &bytes);
    assert_ne!(ours, other);
    assert_eq!(AUDIT_DOMAIN_V1, b"vestry.audit.event.v1");
}

#[test]
fn canonical_rules_reject_float_null_control_and_hash_field() {
    let float = br#"{"sequence":1,"previous_hash":"x","schema_version":1,"actor":{},"action":{},"scope":{},"policy_refs":[],"evidence_refs":[],"outcome":{},"recorded_at_ms":1.5}"#;
    assert_eq!(
        canonicalize_json_bytes(float),
        Err(CanonicalError::FloatNotAllowed)
    );

    let null = br#"{"sequence":1,"previous_hash":"x","schema_version":1,"actor":null,"action":{},"scope":{},"policy_refs":[],"evidence_refs":[],"outcome":{},"recorded_at_ms":1}"#;
    assert_eq!(
        canonicalize_json_bytes(null),
        Err(CanonicalError::NullNotAllowed)
    );

    let with_hash = br#"{"sequence":1,"previous_hash":"x","schema_version":1,"actor":{},"action":{},"scope":{},"policy_refs":[],"evidence_refs":[],"outcome":{},"recorded_at_ms":1,"event_hash":"00"}"#;
    assert_eq!(
        canonicalize_json_bytes(with_hash),
        Err(CanonicalError::HashFieldPresent)
    );

    // A raw control byte is invalid JSON; the typed writer rejects the value
    // directly, and that is the audit path.
    let control = "{\"sequence\":1,\"previous_hash\":\"x\",\"schema_version\":1,\"actor\":\"a\u{0001}b\",\"action\":{},\"scope\":{},\"policy_refs\":[],\"evidence_refs\":[],\"outcome\":{},\"recorded_at_ms\":1}";
    assert_eq!(
        canonicalize_json_bytes(control.as_bytes()),
        Err(CanonicalError::InvalidJson)
    );
    assert_eq!(
        encode_canon(&Canon::Str("a\u{0001}b")),
        Err(CanonicalError::ControlCharacter)
    );

    let missing = br#"{"sequence":1}"#;
    assert!(matches!(
        canonicalize_json_bytes(missing),
        Err(CanonicalError::MissingField(_))
    ));

    let unknown = br#"{"sequence":1,"previous_hash":"x","schema_version":1,"actor":{},"action":{},"scope":{},"policy_refs":[],"evidence_refs":[],"outcome":{},"recorded_at_ms":1,"extra":true}"#;
    assert!(matches!(
        canonicalize_json_bytes(unknown),
        Err(CanonicalError::UnknownField(_))
    ));
}
