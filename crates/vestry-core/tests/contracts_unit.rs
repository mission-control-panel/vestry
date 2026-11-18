//! Contract-level model-free tests (T41 §7.2): no network, no credential, no
//! process, no live model. These are mechanism checks, not qualification.

use vestry_core::contracts::adapter::{
    AdapterError, Architecture, CanaryEvidence, CanaryEvidenceGap, CanaryRecord, CanaryValidity,
    CapabilityEntry, CapabilityId, CapabilityManifest, CapabilityState, DispatchPath,
    EnvironmentAllowlist, EnvironmentValue, IdentityRecord, MalformedClass, ManifestValidity,
    NormalizedEvent, OperatingSystem, PermissionAction, PermissionPolicy, PermissionRule, Platform,
    Role, SessionObservation, TokenCounters, ToolName, UsageSource, UsageStep, UsageStepKey,
};
use vestry_core::contracts::audit::{
    AuditAction, AuditActor, AuditEventDraft, AuditOperation, AuditOutcome, AuditReason, AuditScope,
};
use vestry_core::contracts::certificate::{
    CertificateAbsentReason, CertificateVerdict, CertificateVerifier,
    FailClosedCertificateVerifier, FailClosedWorkerGate, WorkerDispatchGate,
};
use vestry_core::contracts::dispatch::{
    AnchoredInvocation, BindingKind, CanonicalBytes, DispatchBinding, DispatchBindingError,
    DispatchCommon, Gate, GateRef, PathSnapshot, PluginOrigin, PluginSnapshot, PreAnchorDiscovery,
    RoleBinding, TaskBinding,
};
use vestry_core::contracts::doctor::AdapterSessionRecord;
use vestry_core::contracts::pin::{
    AdapterVersion, ApiAliasOrTag, CredentialRef, DataCollection, Endpoint, EnvironmentName,
    IdentityChannel, LogicalModelId, ModelPin, PinError, PinField, ProviderId, RoutePolicy,
    TargetKind,
};
use vestry_core::contracts::primitives::{
    AdmissionId, AnchorId, AttemptId, CertificateId, CreationFiletime, CriterionId,
    DaemonGeneration, DispatchOrdinal, EvidenceId, Fence, FingerprintDigest, GitSha, GoalId,
    Hash32, LeaseId, ManifestId, PinRevision, RedactionVersion, Revision, RouteFingerprint,
    SafeCode, SafeId, SafeRelativePath, SafeText, ScratchScope, Sha256Digest, StateRequestId,
    TaskId, UtcMillis, WindowsAbsolutePath,
};
use vestry_core::contracts::process::{
    EnumerationCompleteness, EnumerationLimit, ProcessEnumeration, ProcessIdentity,
    ProofLimitation, TerminationProof,
};
use vestry_core::contracts::schema::{
    SchemaCompatibility, SchemaVersion, CURRENT_SCHEMA_VERSION, EXPECTED_TABLE_COUNT, TABLE_NAMES,
};
use vestry_core::contracts::state::{
    RecoveryView, StateError, StateMutation, StateOp, StateTarget, StateTxn,
};
use vestry_core::contracts::status::{
    AttemptState, BlockCondition, BlockOwner, BlockReason, EvidenceIntegrity, EvidenceRecord,
    EvidenceState, EvidenceStatus, EvidenceType, NeverPaidInvariant, NotRunReason, SafeArtifactRef,
    StatusError, TaskState, UnblockCondition,
};

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
}

fn free_tier_pin() -> ModelPin {
    ModelPin {
        pin_revision: PinField::Present(PinRevision::FIRST),
        target_kind: PinField::Present(TargetKind::FreeTier),
        provider: PinField::Present(ProviderId::new("openrouter").unwrap()),
        logical_model: PinField::Present(LogicalModelId::new("model").unwrap()),
        api_alias_or_tag: PinField::Present(ApiAliasOrTag::new("model:free").unwrap()),
        weight_digest: PinField::Absent,
        runtime_version: PinField::Absent,
        model_details: PinField::Absent,
        endpoint: PinField::Present(Endpoint::new("https://openrouter.ai/api").unwrap()),
        route_policy: PinField::Present(RoutePolicy {
            allow_fallbacks: false,
            order: vec![],
            only: vec![],
            require_parameters: true,
            data_collection: DataCollection::Deny,
            disable_model_fallback: true,
            disable_provider_fallback: true,
        }),
        identity_channel: PinField::Present(IdentityChannel::OpenRouterGeneration),
        adapter_executable_digest: PinField::Present(digest(0x11)),
        adapter_version: PinField::Present(AdapterVersion::new("1").unwrap()),
        config_digest: PinField::Present(digest(0x22)),
        credential_ref: PinField::Present(CredentialRef::new("credential:openrouter").unwrap()),
        allowed_variants: PinField::Absent,
    }
}

// ---------------------------------------------------------------------------
// C3 pin
// ---------------------------------------------------------------------------

#[test]
fn pin_presence_matrix_is_exact_and_null_is_malformed() {
    assert!(free_tier_pin().validate().is_ok());

    // Explicit JSON null is never the design's absent.
    let null: Result<ModelPin, _> = serde_json::from_str(r#"{"weight_digest":null}"#);
    assert!(null.is_err(), "null must not deserialize as Absent");

    let mut wrong = free_tier_pin();
    wrong.weight_digest = PinField::Present(digest(0x33));
    assert!(matches!(
        wrong.validate(),
        Err(PinError::FieldMustBeAbsent {
            field: "weight_digest"
        })
    ));

    let mut missing = free_tier_pin();
    missing.credential_ref = PinField::Absent;
    assert!(matches!(
        missing.validate(),
        Err(PinError::MissingRequiredField {
            field: "credential_ref"
        })
    ));

    // Exactly two target kinds exist.
    let kinds = [TargetKind::LocalOpenWeight, TargetKind::FreeTier];
    assert_eq!(kinds.len(), 2);

    // Groq is fail-closed on the unverified identity channel.
    let mut groq = free_tier_pin();
    groq.identity_channel = PinField::Present(IdentityChannel::GroqUnverified);
    assert!(matches!(groq.validate(), Err(PinError::GroqUnverified)));
}

#[test]
fn pin_fallback_and_revision_are_fail_closed() {
    let mut route = free_tier_pin();
    if let PinField::Present(policy) = &mut route.route_policy {
        policy.allow_fallbacks = true;
    }
    assert!(matches!(route.validate(), Err(PinError::FallbackEnabled)));

    let mut revision = free_tier_pin();
    revision.pin_revision = PinField::Present(PinRevision(0));
    assert!(matches!(
        revision.validate(),
        Err(PinError::InvalidPinRevision)
    ));
}

// ---------------------------------------------------------------------------
// C6 status
// ---------------------------------------------------------------------------

#[test]
fn evidence_status_is_tri_state_with_closed_wire_values() {
    assert!(EvidenceStatus::pass().validate().is_ok());
    assert!(EvidenceStatus::fail(None).validate().is_ok());
    assert!(EvidenceStatus::not_run(NotRunReason::Availability)
        .validate()
        .is_ok());
    assert!(EvidenceStatus::pass().is_pass());

    let unset = EvidenceStatus {
        state: EvidenceState::NotRun,
        not_run_reason: None,
        failure_code: None,
    };
    assert!(matches!(
        unset.validate(),
        Err(StatusError::NotRunWithoutReason)
    ));

    let pass_with_reason = EvidenceStatus {
        state: EvidenceState::Pass,
        not_run_reason: Some(NotRunReason::Availability),
        failure_code: None,
    };
    assert!(matches!(
        pass_with_reason.validate(),
        Err(StatusError::ReasonOnNonNotRun)
    ));

    assert_eq!(
        serde_json::from_str::<EvidenceState>("\"not_run\"").unwrap(),
        EvidenceState::NotRun
    );
    assert!(serde_json::from_str::<EvidenceState>("\"blocked\"").is_err());
    assert!(serde_json::from_str::<EvidenceState>("\"recovery_required\"").is_err());
}

#[test]
fn blocked_is_a_condition_and_not_evidence() {
    let block = BlockCondition {
        owner: BlockOwner::Daemon,
        reason: BlockReason::TerminationUnproven,
        unblock: UnblockCondition::CurrentOwnedProcessProof,
    };
    assert_eq!(serde_json::to_string(&block).unwrap(), "{\"owner\":\"daemon\",\"reason\":\"termination_unproven\",\"unblock\":\"current_owned_process_proof\"}");

    assert!(!NotRunReason::FixtureOnly.is_product_eligible());
    assert!(!NotRunReason::PhaseBNotImplemented.is_product_eligible());
    assert!(NotRunReason::Availability.is_product_eligible());

    assert!(TaskState::IntegratedClosed.is_terminal());
    assert!(TaskState::Withdrawn.is_terminal());
    assert!(TaskState::Cancelled.is_terminal());
    assert!(!TaskState::Blocked.is_terminal());
    assert!(!TaskState::RecoveryRequired.is_terminal());
}

#[test]
fn evidence_record_supports_pass_only_when_verified() {
    let mut record = EvidenceRecord {
        evidence_id: EvidenceId::new("ev_01").unwrap(),
        artefact: SafeArtifactRef {
            relative_path: SafeRelativePath::new("evidence/termination/abc.json").unwrap(),
            digest: digest(0x01),
            bytes: 10,
        },
        evidence_type: EvidenceType::TerminationProof,
        producer: AuditActor::Supervisor {
            generation: DaemonGeneration(1),
        },
        revision: Revision(1),
        redaction_version: RedactionVersion::V1,
        integrity: EvidenceIntegrity::Unavailable,
        created_at_ms: UtcMillis(1),
    };
    assert!(!record.supports_pass());
    record.integrity = EvidenceIntegrity::Verified;
    assert!(record.supports_pass());
}

#[test]
fn failure_taxonomy_never_maps_to_pass() {
    use vestry_core::contracts::adapter::PinFailure;
    let all = [
        PinFailure::QuotaBeforeInference,
        PinFailure::QuotaAfterInference,
        PinFailure::ModelRetired,
        PinFailure::ProviderFallback,
        PinFailure::ServedIdentityMissing,
        PinFailure::ServedIdentityMismatch,
        PinFailure::MidSessionDivergence,
        PinFailure::LocalDigestMismatch,
        PinFailure::TransportAuth,
        PinFailure::OpaqueRoute,
    ];
    for failure in all {
        let disposition = failure.disposition();
        assert_eq!(disposition.evidence, EvidenceState::NotRun);
        assert!(disposition.item_blocked);
    }
    assert_eq!(all.len(), 10);
    assert_eq!(
        PinFailure::QuotaBeforeInference.never_paid_clauses(),
        vec![
            NeverPaidInvariant::NoPaidRoute,
            NeverPaidInvariant::NoCreditPurchase
        ]
    );
}

// ---------------------------------------------------------------------------
// C3 canary / environment / usage / identity
// ---------------------------------------------------------------------------

fn canary(result: EvidenceStatus, evidence: CanaryEvidence) -> CanaryRecord {
    CanaryRecord {
        canary_id: vestry_core::contracts::primitives::CanaryId::new("canary_01").unwrap(),
        manifest_id: ManifestId::new("manifest_01").unwrap(),
        dispatch_path: DispatchPath::CliDefault,
        role: Role::Discovery,
        policy_digest: digest(0x44),
        model_pin: free_tier_pin(),
        route_fingerprint: RouteFingerprint(digest(0x55)),
        result,
        evidence,
        evidence_digest: digest(0x66),
        observed_at: UtcMillis(1),
        validity: CanaryValidity::Current,
    }
}

#[test]
fn canary_pass_requires_machine_evidence() {
    let prose_only = canary(
        EvidenceStatus::pass(),
        CanaryEvidence::Insufficient {
            reason: CanaryEvidenceGap::ModelProseOnly,
        },
    );
    assert!(prose_only.validate().is_err());
    assert!(!prose_only.is_current_pass());

    let mut inventory = canary(
        EvidenceStatus::pass(),
        CanaryEvidence::FinalToolInventory {
            session_id: vestry_core::contracts::primitives::SessionId::new("s1").unwrap(),
            inventory_digest: digest(0x77),
            tool_names: vec![
                ToolName(SafeCode::new("read").unwrap()),
                ToolName(SafeCode::new("write").unwrap()),
            ],
        },
    );
    assert!(inventory.validate().is_ok());
    assert!(inventory.is_current_pass());
    inventory.validity = CanaryValidity::Invalidated {
        reason: vestry_core::contracts::adapter::CanaryInvalidation::PinChanged,
        at: UtcMillis(2),
    };
    assert!(!inventory.is_current_pass());

    let not_run = canary(
        EvidenceStatus::not_run(NotRunReason::CanaryEvidenceIncomplete),
        CanaryEvidence::Insufficient {
            reason: CanaryEvidenceGap::NoToolUseObserved,
        },
    );
    assert!(not_run.validate().is_ok());
    assert!(!not_run.is_current_pass());

    let mut private = canary(
        EvidenceStatus::pass(),
        CanaryEvidence::FinalToolInventory {
            session_id: vestry_core::contracts::primitives::SessionId::new("s2").unwrap(),
            inventory_digest: digest(0x78),
            tool_names: vec![ToolName(SafeCode::new("read").unwrap())],
        },
    );
    private.dispatch_path = DispatchPath::PrivateServe;
    assert!(private.validate().is_err());
}

#[test]
fn environment_is_total_and_references_secrets() {
    let empty = EnvironmentAllowlist::empty();
    let baseline = empty.fingerprint().unwrap();

    let mut literal = EnvironmentAllowlist::empty();
    literal.entries.insert(
        EnvironmentName::new("OPENCODE_PERMISSION").unwrap(),
        EnvironmentValue::Literal("{}".to_owned()),
    );
    let literal_fingerprint = literal.fingerprint().unwrap();
    assert_ne!(literal_fingerprint, baseline);

    let mut reference = EnvironmentAllowlist::empty();
    reference.entries.insert(
        EnvironmentName::new("OPENCODE_PERMISSION").unwrap(),
        EnvironmentValue::SecretRef(CredentialRef::new("credential:openrouter").unwrap()),
    );
    assert_ne!(reference.fingerprint().unwrap(), literal_fingerprint);

    let mut bad = EnvironmentAllowlist::empty();
    bad.entries.insert(
        EnvironmentName::new("OPENCODE_PERMISSION").unwrap(),
        EnvironmentValue::Literal("line\nbreak".to_owned()),
    );
    assert!(bad.validate().is_err());

    let policy = PermissionPolicy {
        rules: vec![
            PermissionRule {
                pattern: SafeText::new("*").unwrap(),
                action: PermissionAction::Ask,
            },
            PermissionRule {
                pattern: SafeText::new("bash").unwrap(),
                action: PermissionAction::Allow,
            },
        ],
    };
    assert!(policy.validate().is_ok());
    assert!(PermissionPolicy::from_json(b"not json").is_err());

    let late_wildcard = PermissionPolicy {
        rules: vec![
            PermissionRule {
                pattern: SafeText::new("bash").unwrap(),
                action: PermissionAction::Allow,
            },
            PermissionRule {
                pattern: SafeText::new("*").unwrap(),
                action: PermissionAction::Ask,
            },
        ],
    };
    assert!(late_wildcard.validate().is_err());
}

#[test]
fn usage_zero_cost_is_reported_not_unknown() {
    let step = |cost: Option<f64>| UsageStep {
        key: UsageStepKey {
            attempt_id: AttemptId::new("att_01").unwrap(),
            session_id: vestry_core::contracts::primitives::SessionId::new("s1").unwrap(),
            part_id: vestry_core::contracts::primitives::PartId::new("p1").unwrap(),
        },
        counters: TokenCounters {
            input: 1,
            output: 1,
            cache_read: None,
            cache_write: None,
            reasoning: None,
            total: None,
        },
        cost,
        model_evidence: vestry_core::contracts::primitives::ModelEvidenceRef::new("me_1").unwrap(),
        duration_ms: None,
        source: UsageSource::StepFinishStdout,
    };
    assert!(step(Some(0.0)).validate().is_ok());
    assert!(step(None).validate().is_ok());
    assert!(step(Some(-0.1)).validate().is_err());
    assert!(step(Some(f64::NAN)).validate().is_err());
    assert_ne!(step(Some(0.0)).cost, None);
}

#[test]
fn exit_zero_alone_is_not_success() {
    let observation = SessionObservation {
        events: vec![],
        stream_complete: false,
        exit_code: Some(0),
        stderr_digest: None,
    };
    assert!(!observation.is_acceptable_success());

    let with_malformed = SessionObservation {
        events: vec![NormalizedEvent::Malformed {
            class: MalformedClass::Ansi,
        }],
        stream_complete: true,
        exit_code: Some(0),
        stderr_digest: None,
    };
    assert!(!with_malformed.is_acceptable_success());

    let clean = SessionObservation {
        events: vec![],
        stream_complete: true,
        exit_code: Some(0),
        stderr_digest: None,
    };
    assert!(clean.is_acceptable_success());
}

#[test]
fn capability_and_identity_fail_closed() {
    assert!(CapabilityState::Supported.is_available(true));
    assert!(!CapabilityState::Conditional.is_available(false));
    assert!(!CapabilityState::Unverified.is_available(true));
    assert!(!CapabilityState::Unsupported.is_available(true));

    let manifest = CapabilityManifest {
        manifest_id: ManifestId::new("m1").unwrap(),
        schema_version: 1,
        adapter_id: vestry_core::contracts::pin::AdapterId::new("adapter").unwrap(),
        installation_version: vestry_core::contracts::pin::InstallationVersion::new("1").unwrap(),
        executable_digest: digest(0x01),
        environment_fingerprint: vestry_core::contracts::primitives::EnvironmentFingerprint(
            digest(0x02),
        ),
        policy_profile_digest: digest(0x03),
        requested_model_pin: free_tier_pin(),
        qualified_at: UtcMillis(1),
        platform: Platform {
            os: OperatingSystem::Windows,
            arch: Architecture::X86_64,
        },
        evidence_revision: vestry_core::contracts::primitives::EvidenceRevision(1),
        capabilities: vec![CapabilityEntry {
            id: CapabilityId::StepUsage,
            state: CapabilityState::Conditional,
            conditions: vec![],
            proof_ids: vec![],
            limitations: vec![],
        }],
        validity: ManifestValidity::Current,
    };
    assert!(manifest.validate().is_err());
    // A conditional capability is unavailable unless the caller has proven its
    // conditions current; an unknown id is unavailable outright.
    assert!(matches!(
        manifest.require(CapabilityId::StepUsage, false),
        Err(AdapterError::CapabilityUnavailable(CapabilityId::StepUsage))
    ));
    assert!(matches!(
        manifest.require(CapabilityId::SessionResume, true),
        Err(AdapterError::CapabilityUnavailable(
            CapabilityId::SessionResume
        ))
    ));

    let mut stale = manifest.clone();
    stale.validity = ManifestValidity::Invalidated {
        reason: vestry_core::contracts::adapter::ManifestInvalidation::FingerprintChanged,
        at: UtcMillis(2),
    };
    assert!(matches!(
        stale.require(CapabilityId::StepUsage, true),
        Err(AdapterError::ManifestNotCurrent(_))
    ));

    let identity = IdentityRecord {
        requested: free_tier_pin(),
        resolved: None,
        outbound: None,
        served: None,
        provenance: vec![],
    };
    assert!(!identity.fields_are_separate());
    assert_eq!(
        identity.validate().unwrap_err(),
        vestry_core::contracts::adapter::PinFailure::ServedIdentityMissing
    );

    // Two provider responses on the served identity are a substitution.
    let substituted = IdentityRecord {
        requested: free_tier_pin(),
        resolved: None,
        outbound: None,
        served: Some(
            vestry_core::contracts::adapter::ServedIdentity::OpenRouterGeneration {
                generation_id: SafeText::new("gen_1").unwrap(),
                model: SafeText::new("model").unwrap(),
                provider_name: vestry_core::contracts::pin::ProviderSlug::new("a").unwrap(),
                provider_responses: vec![
                    vestry_core::contracts::adapter::ProviderResponse {
                        model: SafeText::new("model").unwrap(),
                        provider_name: vestry_core::contracts::pin::ProviderSlug::new("a").unwrap(),
                        model_permaslug: SafeText::new("model-a").unwrap(),
                    },
                    vestry_core::contracts::adapter::ProviderResponse {
                        model: SafeText::new("model").unwrap(),
                        provider_name: vestry_core::contracts::pin::ProviderSlug::new("b").unwrap(),
                        model_permaslug: SafeText::new("model-b").unwrap(),
                    },
                ],
                observed_at: UtcMillis(1),
            },
        ),
        provenance: vec![],
    };
    assert_eq!(
        substituted.validate().unwrap_err(),
        vestry_core::contracts::adapter::PinFailure::ProviderFallback
    );
}

// ---------------------------------------------------------------------------
// C3 dispatch binding
// ---------------------------------------------------------------------------

fn common() -> DispatchCommon {
    DispatchCommon {
        executable_digest: digest(0x01),
        arguments: vec!["run".to_owned()],
        config_bytes: CanonicalBytes::new(b"{}".to_vec()),
        policy_bytes: CanonicalBytes::new(b"{}".to_vec()),
        shell_path: None,
        path_snapshot: PathSnapshot {
            entries: vec![],
            resolved_executable: WindowsAbsolutePath::new("C:\\bin\\adapter.exe").unwrap(),
        },
        plugin_snapshot: PluginSnapshot {
            configured_origins: vec![PluginOrigin(SafeText::new("none").unwrap())],
            observed_origins: vec![PluginOrigin(SafeText::new("none").unwrap())],
            fingerprint: digest(0x02),
        },
        model_pin: free_tier_pin(),
        credential_refs: vec![CredentialRef::new("credential:openrouter").unwrap()],
    }
}

fn discovery(role: Role) -> PreAnchorDiscovery {
    PreAnchorDiscovery {
        common: common(),
        goal_id: GoalId::new("goal_01").unwrap(),
        intake_digest: digest(0x11),
        intake_revision: Revision(1),
        target_digest: digest(0x22),
        scratch_scope: ScratchScope::new("scratch/goal_01").unwrap(),
        role,
        admission_id: AdmissionId::new("adm_01").unwrap(),
        attempt_id: AttemptId::new("att_01").unwrap(),
        dispatch_ordinal: DispatchOrdinal::FIRST,
        fence: Fence::INITIAL,
    }
}

fn anchored() -> AnchoredInvocation {
    let gate_ref = |gate| GateRef {
        gate,
        artefact_digest: digest(0x03),
        revision: Revision(7),
    };
    AnchoredInvocation {
        common: common(),
        goal_id: GoalId::new("goal_01").unwrap(),
        anchor_id: AnchorId::new("anc_01").unwrap(),
        criterion_ids: vec![CriterionId::new("crit_01").unwrap()],
        role_binding: RoleBinding::Worker {
            gate1: gate_ref(Gate::Gate1),
            gate2: gate_ref(Gate::Gate2),
            gate3: gate_ref(Gate::Gate3),
            task: TaskBinding {
                task_id: TaskId::new("task_01").unwrap(),
                task_revision: Revision(3),
                lease_id: LeaseId::new("lease_01").unwrap(),
                base_sha: GitSha::from_hex(&"ab".repeat(20)).unwrap(),
            },
            certificate_id: CertificateId::new("cert_01").unwrap(),
        },
        admission_id: AdmissionId::new("adm_01").unwrap(),
        attempt_id: AttemptId::new("att_01").unwrap(),
        dispatch_ordinal: DispatchOrdinal::FIRST,
        fence: Fence::INITIAL,
    }
}

#[test]
fn dispatch_binding_roles_are_structural() {
    let wrong = DispatchBinding::PreAnchorDiscovery(discovery(Role::Architect));
    assert!(matches!(
        wrong.validate(),
        Err(DispatchBindingError::PreAnchorRoleNotDiscovery)
    ));

    let good = DispatchBinding::PreAnchorDiscovery(discovery(Role::Discovery));
    assert!(good.validate().is_ok());
    assert_eq!(good.kind(), BindingKind::PreAnchorDiscovery);
    // Discovery structurally cannot fabricate an anchor or criteria.
    let discovery_json = serde_json::to_string(&good).unwrap();
    assert!(!discovery_json.contains("anchor_id"));
    assert!(!discovery_json.contains("criterion_ids"));
    assert!(discovery_json.contains("\"kind\":\"pre_anchor_discovery\""));

    let mut empty = anchored();
    empty.criterion_ids.clear();
    assert!(matches!(
        DispatchBinding::AnchoredInvocation(empty).validate(),
        Err(DispatchBindingError::EmptyCriteria)
    ));

    let worker = DispatchBinding::AnchoredInvocation(anchored());
    assert!(worker.validate().is_ok());
    assert_eq!(worker.kind(), BindingKind::AnchoredInvocation);

    assert_eq!(
        GateRef {
            gate: Gate::Gate2,
            artefact_digest: digest(0x03),
            revision: Revision(7),
        }
        .artefact_ref()
        .as_str(),
        "gate:2:rev7"
    );
}

#[test]
fn dispatch_common_rejects_unresolved_credential_and_plugin_drift() {
    let mut unresolved = anchored();
    unresolved.common.credential_refs.clear();
    assert!(matches!(
        DispatchBinding::AnchoredInvocation(unresolved).validate(),
        Err(DispatchBindingError::UnresolvedCredentialRef)
    ));

    let mut drift = anchored();
    drift.common.plugin_snapshot.observed_origins =
        vec![PluginOrigin(SafeText::new("unexpected").unwrap())];
    assert!(matches!(
        DispatchBinding::AnchoredInvocation(drift).validate(),
        Err(DispatchBindingError::PluginSnapshotMismatch)
    ));

    let mut nul = anchored();
    nul.common.arguments = vec!["a\0b".to_owned()];
    assert!(matches!(
        DispatchBinding::AnchoredInvocation(nul).validate(),
        Err(DispatchBindingError::InvalidArgument)
    ));
}

#[test]
fn plugin_snapshot_requires_the_exact_origin_vector() {
    let origin = |text: &str| PluginOrigin(SafeText::new(text).unwrap());
    let verdict = |configured: Vec<PluginOrigin>, observed: Vec<PluginOrigin>| {
        let mut binding = anchored();
        binding.common.plugin_snapshot.configured_origins = configured;
        binding.common.plugin_snapshot.observed_origins = observed;
        DispatchBinding::AnchoredInvocation(binding).validate()
    };

    // Shorter observed list: a configured origin was never loaded.
    assert!(matches!(
        verdict(vec![origin("a"), origin("b")], vec![origin("a")]),
        Err(DispatchBindingError::PluginSnapshotMismatch)
    ));
    // Longer observed list: an unexpected origin was loaded.
    assert!(matches!(
        verdict(vec![origin("a")], vec![origin("a"), origin("b")]),
        Err(DispatchBindingError::PluginSnapshotMismatch)
    ));
    // Equal length but a different element.
    assert!(matches!(
        verdict(
            vec![origin("a"), origin("b")],
            vec![origin("a"), origin("c")]
        ),
        Err(DispatchBindingError::PluginSnapshotMismatch)
    ));
    // Equal length, same elements, different order.
    assert!(matches!(
        verdict(
            vec![origin("a"), origin("b")],
            vec![origin("b"), origin("a")]
        ),
        Err(DispatchBindingError::PluginSnapshotMismatch)
    ));
    // Identical vectors pass, including a multi-element snapshot.
    assert!(verdict(Vec::new(), Vec::new()).is_ok());
    assert!(verdict(
        vec![origin("a"), origin("b")],
        vec![origin("a"), origin("b")]
    )
    .is_ok());
}

#[test]
fn canonical_bytes_are_not_json_decodable() {
    let bytes = CanonicalBytes::new(b"{}".to_vec());
    let json = serde_json::to_string(&bytes).unwrap();
    assert!(json.contains("\"length\":2"));
    assert!(serde_json::from_str::<CanonicalBytes>(&json).is_err());

    let mut tampered = bytes.clone();
    tampered.digest = digest(0xff);
    assert!(tampered.validate().is_err());
}

// ---------------------------------------------------------------------------
// C7 schema
// ---------------------------------------------------------------------------

#[test]
fn c7_schema_constants_are_frozen() {
    assert_eq!(CURRENT_SCHEMA_VERSION, SchemaVersion(1));
    assert_eq!(TABLE_NAMES.len(), EXPECTED_TABLE_COUNT);
    let mut names = TABLE_NAMES.to_vec();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), EXPECTED_TABLE_COUNT, "table names are unique");
    assert!(TABLE_NAMES.contains(&"audit_events"));
    assert!(TABLE_NAMES.contains(&"readiness_certificates"));

    assert!(SchemaCompatibility::Current.permits_write_startup());
    assert!(!SchemaCompatibility::UnsupportedNewer {
        found: SchemaVersion(2),
        supported: SchemaVersion(1),
    }
    .permits_write_startup());
}

// ---------------------------------------------------------------------------
// C8 primitives
// ---------------------------------------------------------------------------

#[test]
fn c8_ids_time_and_digests_roundtrip() {
    let id = GoalId::new("goal_01").unwrap();
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, "\"goal_01\"");
    assert_eq!(serde_json::from_str::<GoalId>(&json).unwrap(), id);

    assert!(SafeId::new("has space").is_err());
    assert!(SafeId::new("slash/inside").is_err());
    assert!(SafeId::new("").is_err());
    assert!(SafeId::new("quote\"inside").is_err());

    // FILETIME is stored losslessly, never rounded through SystemTime.
    let exact = CreationFiletime(u64::MAX);
    let roundtrip = serde_json::to_string(&exact).unwrap();
    assert_eq!(
        serde_json::from_str::<CreationFiletime>(&roundtrip).unwrap(),
        exact
    );

    // Digest encoding carries the algorithm prefix on both directions.
    let sha = digest(0xab);
    let encoded = serde_json::to_string(&sha).unwrap();
    assert_eq!(encoded, format!("\"sha256:{}\"", "ab".repeat(32)));
    assert_eq!(serde_json::from_str::<Sha256Digest>(&encoded).unwrap(), sha);

    let git = GitSha::from_hex(&"cd".repeat(20)).unwrap();
    assert_eq!(
        serde_json::to_string(&git).unwrap(),
        format!("\"git:{}\"", "cd".repeat(20))
    );
    assert_eq!(Hash32::ZERO.to_hex(), "0".repeat(64));

    // Initial numeric values are explicit constants, not defaults.
    assert_eq!(Fence::INITIAL, Fence(1));
    assert_eq!(Revision::INITIAL, Revision(0));
    assert_eq!(PinRevision::FIRST, PinRevision(1));
}

// ---------------------------------------------------------------------------
// C2 termination proof
// ---------------------------------------------------------------------------

#[test]
fn c2_proof_requires_empty_complete_enumeration() {
    let identity = ProcessIdentity {
        pid: 7,
        creation_filetime: CreationFiletime(42),
    };
    let proof = TerminationProof {
        dispatch_id: vestry_core::contracts::primitives::DispatchId::new("d1").unwrap(),
        job_generation: vestry_core::contracts::primitives::JobGeneration(1),
        root: identity,
        root_signalled: true,
        enumeration: ProcessEnumeration {
            observed_at_ms: UtcMillis(1),
            identities: vec![],
            active_processes: 0,
            completeness: EnumerationCompleteness::Complete,
        },
        observer: vestry_core::contracts::process::ObserverIdentity::Supervisor {
            generation: DaemonGeneration(1),
        },
        observed_at_ms: UtcMillis(1),
        limitations: vec![],
    };
    assert!(proof.is_complete());

    let mut partial = proof.clone();
    partial.enumeration.completeness = EnumerationCompleteness::Partial {
        reason: EnumerationLimit::Timeout,
    };
    assert!(!partial.is_complete());

    let mut nonempty = proof.clone();
    nonempty.enumeration.identities.push(identity);
    assert!(!nonempty.is_complete());

    let mut accounting = proof.clone();
    accounting.enumeration.active_processes = 1;
    assert!(!accounting.is_complete());

    let mut limited = proof;
    limited
        .limitations
        .push(ProofLimitation::BrokerDescendantsNotContained);
    assert!(!limited.is_complete());
}

// ---------------------------------------------------------------------------
// D27 gate boundary and C4 transaction envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn phase_b_gate_denies_every_worker_dispatch() {
    let verifier = FailClosedCertificateVerifier;
    let verdict = verifier
        .verify(
            CertificateId::new("cert_01").unwrap(),
            FingerprintDigest(digest(0x01)),
        )
        .await
        .unwrap();
    assert_eq!(
        verdict,
        CertificateVerdict::Absent {
            reason: CertificateAbsentReason::PhaseBNotImplemented
        }
    );
    assert!(!verdict.authorizes_worker());

    // Only `Current` authorizes; `Absent`, `Invalid` and any stale verdict do not.
    let current = CertificateVerdict::Current {
        certificate_id: CertificateId::new("cert_01").unwrap(),
        input_fingerprint: FingerprintDigest(digest(0x01)),
    };
    assert!(current.authorizes_worker());
    assert!(!CertificateVerdict::Invalid {
        reason: vestry_core::contracts::certificate::CertificateInvalidReason::StaleFingerprint,
    }
    .authorizes_worker());

    let gate = FailClosedWorkerGate;
    let denial = match gate.authorize(&anchored()) {
        Ok(_) => panic!("Phase B must deny every Worker dispatch"),
        Err(denial) => denial,
    };
    assert_eq!(
        denial,
        vestry_core::contracts::adapter::DispatchDenial::D27CertificateAbsent
    );
}

fn transition() -> StateOp {
    StateOp::TransitionAttempt {
        from: AttemptState::Running,
        to: AttemptState::CancelPending,
    }
}

fn draft() -> AuditEventDraft {
    AuditEventDraft {
        schema_version: 1,
        actor: AuditActor::Supervisor {
            generation: DaemonGeneration(1),
        },
        action: AuditAction::Denial {
            operation: AuditOperation(SafeCode::new("discovery_preflight").unwrap()),
            reason: AuditReason(SafeCode::new("canary_unverified").unwrap()),
        },
        scope: AuditScope::Daemon {
            generation: DaemonGeneration(1),
        },
        policy_refs: vec![],
        evidence_refs: vec![],
        outcome: AuditOutcome::Denied,
        recorded_at_ms: UtcMillis(1),
    }
}

#[test]
fn state_transaction_envelope_is_validated() {
    let request = || StateRequestId::new("req_01").unwrap();

    assert!(matches!(
        StateTxn::new(
            request(),
            DaemonGeneration(1),
            UtcMillis(1),
            vec![],
            vec![],
            vec![]
        ),
        Err(StateError::EmptyTransaction)
    ));

    let attempt = AttemptId::new("att_01").unwrap();
    let mutation = StateMutation {
        target: StateTarget::Attempt(attempt.clone()),
        expected_revision: None,
        op: transition(),
    };
    assert!(matches!(
        StateTxn::new(
            request(),
            DaemonGeneration(1),
            UtcMillis(1),
            vec![mutation.clone(), mutation],
            vec![],
            vec![],
        ),
        Err(StateError::DuplicateTarget(StateTarget::Attempt(_)))
    ));

    // 513 audit drafts exceed the 1 MiB envelope without needing a writer.
    let oversized: Vec<_> = (0..513).map(|_| draft()).collect();
    assert!(matches!(
        StateTxn::new(
            request(),
            DaemonGeneration(1),
            UtcMillis(1),
            vec![],
            oversized,
            vec![],
        ),
        Err(StateError::TransactionTooLarge { .. })
    ));

    let txn = StateTxn::new(
        request(),
        DaemonGeneration(1),
        UtcMillis(1),
        vec![StateMutation {
            target: StateTarget::Attempt(attempt),
            expected_revision: Some(Revision(3)),
            op: transition(),
        }],
        vec![draft()],
        vec![],
    )
    .unwrap();
    assert_eq!(txn.mutations().len(), 1);
    assert_eq!(txn.audit().len(), 1);
    assert!(txn.outbox().is_empty());
}

#[test]
fn recovery_view_carries_adapter_sessions() {
    fn field(view: &RecoveryView) -> &[AdapterSessionRecord] {
        &view.adapter_sessions
    }
    let _ = field;
}
