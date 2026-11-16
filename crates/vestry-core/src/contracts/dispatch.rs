//! C3 dispatch binding (LLD §1 lines 32–34), shared with C5 scope validation.

use serde::{Deserialize, Serialize};

use super::adapter::{Role, ToolName};
use super::pin::{AdapterVersion, CredentialRef, ModelPin};
use super::primitives::{
    AdmissionId, AnchorId, AttemptId, CertificateId, CriterionId, DispatchId, DispatchOrdinal,
    Fence, GateArtefactId, GitSha, GoalId, LeaseId, Revision, SafeId, Sha256Digest, TaskId,
};

pub use super::primitives::WindowsAbsolutePath;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DispatchBinding {
    PreAnchorDiscovery(PreAnchorDiscovery),
    AnchoredInvocation(AnchoredInvocation),
}

impl DispatchBinding {
    pub fn validate(&self) -> Result<(), DispatchBindingError> {
        match self {
            Self::PreAnchorDiscovery(discovery) => discovery.validate(),
            Self::AnchoredInvocation(anchored) => anchored.validate(),
        }
    }

    pub fn kind(&self) -> BindingKind {
        match self {
            Self::PreAnchorDiscovery(_) => BindingKind::PreAnchorDiscovery,
            Self::AnchoredInvocation(_) => BindingKind::AnchoredInvocation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchCommon {
    pub executable_digest: Sha256Digest,
    pub arguments: Vec<String>,
    pub config_bytes: CanonicalBytes,
    pub policy_bytes: CanonicalBytes,
    pub shell_path: Option<WindowsAbsolutePath>,
    pub path_snapshot: PathSnapshot,
    pub plugin_snapshot: PluginSnapshot,
    pub model_pin: ModelPin,
    pub credential_refs: Vec<CredentialRef>,
}

/// Contract type, not a logging type: `bytes` never leave the adapter
/// boundary; only `digest` and length may be recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBytes {
    pub bytes: Vec<u8>,
    pub digest: Sha256Digest,
}

impl CanonicalBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        let digest = Sha256Digest::digest(&bytes);
        Self { bytes, digest }
    }

    pub fn validate(&self) -> Result<(), DispatchBindingError> {
        if Sha256Digest::digest(&self.bytes) != self.digest {
            return Err(DispatchBindingError::CanonicalBytesMismatch);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Serializes as digest + length only; content is not a durable DTO.
impl Serialize for CanonicalBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CanonicalBytes", 2)?;
        state.serialize_field("digest", &self.digest)?;
        state.serialize_field("length", &self.bytes.len())?;
        state.end()
    }
}

/// A dispatch spec with byte payloads cannot be reconstructed from JSON; the
/// decoder refuses rather than yielding an unverifiable binding.
impl<'de> Deserialize<'de> for CanonicalBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let _ = value;
        Err(serde::de::Error::custom(
            "CanonicalBytes is not decodable from JSON; construct it in-process",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathSnapshot {
    pub entries: Vec<WindowsAbsolutePath>,
    pub resolved_executable: WindowsAbsolutePath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSnapshot {
    pub configured_origins: Vec<PluginOrigin>,
    pub observed_origins: Vec<PluginOrigin>,
    pub fingerprint: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PluginOrigin(pub super::primitives::SafeText);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreAnchorDiscovery {
    pub common: DispatchCommon,
    pub goal_id: GoalId,
    pub intake_digest: Sha256Digest,
    pub intake_revision: Revision,
    pub target_digest: Sha256Digest,
    pub scratch_scope: super::primitives::ScratchScope,
    pub role: Role,
    pub admission_id: AdmissionId,
    pub attempt_id: AttemptId,
    pub dispatch_ordinal: DispatchOrdinal,
    pub fence: Fence,
}

impl PreAnchorDiscovery {
    fn validate(&self) -> Result<(), DispatchBindingError> {
        if self.role != Role::Discovery {
            return Err(DispatchBindingError::PreAnchorRoleNotDiscovery);
        }
        self.common.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchoredInvocation {
    pub common: DispatchCommon,
    pub goal_id: GoalId,
    pub anchor_id: AnchorId,
    pub criterion_ids: Vec<CriterionId>,
    pub role_binding: RoleBinding,
    pub admission_id: AdmissionId,
    pub attempt_id: AttemptId,
    pub dispatch_ordinal: DispatchOrdinal,
    pub fence: Fence,
}

impl AnchoredInvocation {
    fn validate(&self) -> Result<(), DispatchBindingError> {
        if self.criterion_ids.is_empty() {
            return Err(DispatchBindingError::EmptyCriteria);
        }
        if !self
            .criterion_ids
            .windows(2)
            .all(|window| window[0] < window[1])
        {
            return Err(DispatchBindingError::DuplicateCriteria);
        }
        self.common.validate()?;
        self.role_binding.validate()
    }

    pub fn role(&self) -> Role {
        self.role_binding.role()
    }
}

impl DispatchCommon {
    fn validate(&self) -> Result<(), DispatchBindingError> {
        if self
            .arguments
            .iter()
            .any(|argument| argument.is_empty() || argument.contains('\0'))
        {
            return Err(DispatchBindingError::InvalidArgument);
        }
        self.config_bytes.validate()?;
        self.policy_bytes.validate()?;
        self.model_pin.validate()?;
        if self
            .plugin_snapshot
            .configured_origins
            .iter()
            .zip(self.plugin_snapshot.observed_origins.iter())
            .any(|(configured, observed)| configured != observed)
        {
            return Err(DispatchBindingError::PluginSnapshotMismatch);
        }
        if let Some(credential) = self.model_pin.credential_ref.as_ref() {
            if self.model_pin.target_kind.as_ref().is_some()
                && !self
                    .credential_refs
                    .iter()
                    .any(|reference| reference == credential)
            {
                return Err(DispatchBindingError::UnresolvedCredentialRef);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum RoleBinding {
    Architect {
        gate1: GateRef,
    },
    Planner {
        gate1: GateRef,
        gate2: GateRef,
    },
    Worker {
        gate1: GateRef,
        gate2: GateRef,
        gate3: GateRef,
        task: TaskBinding,
        certificate_id: CertificateId,
    },
    Reviewer {
        gate1: GateRef,
        gate2: GateRef,
        gate3: GateRef,
        candidate_sha: GitSha,
        review_intent: super::primitives::ReviewIntentRef,
    },
    VerifierJudgement {
        gate1: GateRef,
        gate2: GateRef,
        gate3: GateRef,
        candidate_sha: GitSha,
        check_intent: super::primitives::CheckIntentRef,
    },
}

impl RoleBinding {
    pub fn role(&self) -> Role {
        match self {
            Self::Architect { .. } => Role::Architect,
            Self::Planner { .. } => Role::Planner,
            Self::Worker { .. } => Role::Worker,
            Self::Reviewer { .. } => Role::Reviewer,
            Self::VerifierJudgement { .. } => Role::VerifierJudgement,
        }
    }

    /// The Worker variant structurally carries its task and certificate, so a
    /// Worker binding cannot be constructed without them; the check here
    /// rejects an empty task identity.
    fn validate(&self) -> Result<(), DispatchBindingError> {
        match self {
            Self::Worker {
                task,
                certificate_id,
                ..
            } => {
                if task.task_id.as_str().is_empty() || certificate_id.as_str().is_empty() {
                    return Err(DispatchBindingError::MissingWorkerBinding);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateRef {
    pub gate: Gate,
    pub artefact_digest: Sha256Digest,
    pub revision: Revision,
}

impl GateRef {
    /// `gate_artefacts` identity for the referenced gate revision.
    pub fn artefact_ref(&self) -> GateArtefactId {
        GateArtefactId::new(format!(
            "gate:{}:rev{}",
            self.gate.number(),
            self.revision.get()
        ))
        .expect("gate reference is a safe id")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    Gate1,
    Gate2,
    Gate3,
}

impl Gate {
    pub fn number(self) -> u8 {
        match self {
            Self::Gate1 => 1,
            Self::Gate2 => 2,
            Self::Gate3 => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBinding {
    pub task_id: TaskId,
    pub task_revision: Revision,
    pub lease_id: LeaseId,
    pub base_sha: GitSha,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingKind {
    PreAnchorDiscovery,
    AnchoredInvocation,
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchBindingError {
    #[error("pre-anchor discovery role must be Discovery")]
    PreAnchorRoleNotDiscovery,
    #[error("anchored invocation role binding is missing")]
    MissingRoleBinding,
    #[error("Worker binding is missing its task or certificate")]
    MissingWorkerBinding,
    #[error("criterion list is empty")]
    EmptyCriteria,
    #[error("criterion list is not sorted/unique")]
    DuplicateCriteria,
    #[error("gate binding is missing")]
    MissingGate,
    #[error("credential reference is not in the dispatch allowlist")]
    UnresolvedCredentialRef,
    #[error("canonical bytes digest does not match")]
    CanonicalBytesMismatch,
    #[error("argument contains NUL or is empty")]
    InvalidArgument,
    #[error("path is not absolute")]
    PathNotAbsolute,
    #[error("plugin snapshot is incomplete")]
    PluginSnapshotMismatch,
    #[error("pin is invalid: {0}")]
    Pin(#[from] super::pin::PinError),
}

/// Dispatch is keyed by its opaque identity, never a display value.
pub type DispatchRef = SafeId;

/// Kept for adapters that enumerate tool names in a canary record.
pub type DispatchToolName = ToolName;

/// Adapter version participates in the binding's manifest match; re-exported
/// here so the dispatch surface has no direct pin import in Track 2 code.
pub type BindingAdapterVersion = AdapterVersion;

/// A dispatch's identity is the pair (attempt, ordinal); the id is opaque.
pub fn dispatch_identity(attempt: &AttemptId, ordinal: DispatchOrdinal) -> String {
    format!("{}:{}", attempt.as_str(), ordinal.get())
}

/// Dispatch ids are never derived from the ordinal in a durable field; this
/// helper exists only for diagnostics and is a `SafeId`.
pub fn diagnostic_dispatch_ref(dispatch: &DispatchId) -> String {
    dispatch.as_str().to_owned()
}
