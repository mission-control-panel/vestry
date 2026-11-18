//! C3 model pin: 16 fields with explicit presence, per-target validation.
//!
//! Design sources: LLD §8.1 lines 293–318, §8.2, §8.5; PM decisions Q10, P1-14.
//! `null` is never the design's "absent" (PinField distinguishes the two).

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::primitives::{IdError, SafeText, Sha256Digest, TextError};
use crate::safe_text_newtype;

// ---------------------------------------------------------------------------
// Presence
// ---------------------------------------------------------------------------

/// Distinguishes a missing member (`Absent`) from a present value. A JSON
/// `null` is rejected at deserialization time with `PinError`-style text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PinField<T> {
    #[default]
    Absent,
    Present(T),
}

impl<T> PinField<T> {
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Absent => None,
            Self::Present(v) => Some(v),
        }
    }

    pub fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }
}

impl<T: Serialize> Serialize for PinField<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Absent => serializer.serialize_none(),
            Self::Present(value) => value.serialize(serializer),
        }
    }
}

struct PinFieldVisitor<T>(std::marker::PhantomData<T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for PinFieldVisitor<T> {
    type Value = PinField<T>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a present pin field value (null is not the design's absent)")
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        T::deserialize(deserializer).map(PinField::Present)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Err(E::custom(
            "PinError::NullIsNotAbsent: null is not the design's absent",
        ))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Err(E::custom(
            "PinError::NullIsNotAbsent: null is not the design's absent",
        ))
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PinField<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_option(PinFieldVisitor(std::marker::PhantomData))
    }
}

// ---------------------------------------------------------------------------
// Domain newtypes used by the pin
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderId(pub SafeText);

impl ProviderId {
    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        Ok(Self(SafeText::new(value)?))
    }
}

safe_text_newtype!(LogicalModelId);
safe_text_newtype!(ApiAliasOrTag);
safe_text_newtype!(RuntimeVersion);
safe_text_newtype!(AdapterVersion);
safe_text_newtype!(InstallationVersion);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderSlug(pub SafeText);

impl ProviderSlug {
    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let text = SafeText::new(value)?;
        if text.as_str().is_empty() {
            return Err(TextError::Empty);
        }
        Ok(Self(text))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialRef(pub SafeText);

impl CredentialRef {
    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let text = SafeText::new(value)?;
        if text.as_str().is_empty() {
            return Err(TextError::Empty);
        }
        Ok(Self(text))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdapterId(pub super::primitives::SafeId);

impl AdapterId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        Ok(Self(super::primitives::SafeId::new(value)?))
    }
}

/// Endpoint shape: loopback HTTP for local runtimes, HTTPS for free-tier
/// providers; no userinfo. Provider allowlists remain Phase C policy data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Endpoint(pub SafeText);

impl Endpoint {
    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let text = SafeText::new(value)?;
        let raw = text.as_str();
        if raw.is_empty() {
            return Err(TextError::Empty);
        }
        if raw.contains('@') {
            // userinfo is never part of a contract endpoint
            return Err(TextError::InvalidCharacter);
        }
        if !(raw.starts_with("http://") || raw.starts_with("https://")) {
            return Err(TextError::InvalidCharacter);
        }
        Ok(Self(text))
    }

    pub fn is_loopback(&self) -> bool {
        let raw = self.0.as_str();
        let Some(rest) = raw.strip_prefix("http://") else {
            return false;
        };
        let host = rest.split(['/', ':']).next().unwrap_or("");
        host == "127.0.0.1" || host == "localhost" || host == "[::1]"
    }

    pub fn is_https(&self) -> bool {
        self.0.as_str().starts_with("https://")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentName(pub String);

impl EnvironmentName {
    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        let mut chars = value.chars();
        let Some(first) = chars.next() else {
            return Err(TextError::Empty);
        };
        if !(first.is_ascii_uppercase() || first == '_') {
            return Err(TextError::InvalidCharacter);
        }
        for ch in chars {
            if !(ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_') {
                return Err(TextError::InvalidCharacter);
            }
        }
        Ok(Self(value))
    }
}

impl std::fmt::Display for EnvironmentName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialOrd for EnvironmentName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EnvironmentName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

// ---------------------------------------------------------------------------
// Pin record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPin {
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub pin_revision: PinField<super::primitives::PinRevision>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub target_kind: PinField<TargetKind>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub provider: PinField<ProviderId>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub logical_model: PinField<LogicalModelId>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub api_alias_or_tag: PinField<ApiAliasOrTag>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub weight_digest: PinField<Sha256Digest>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub runtime_version: PinField<RuntimeVersion>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub model_details: PinField<ModelDetails>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub endpoint: PinField<Endpoint>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub route_policy: PinField<RoutePolicy>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub identity_channel: PinField<IdentityChannel>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub adapter_executable_digest: PinField<Sha256Digest>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub adapter_version: PinField<AdapterVersion>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub config_digest: PinField<Sha256Digest>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub credential_ref: PinField<CredentialRef>,
    #[serde(default, skip_serializing_if = "PinField::is_absent")]
    pub allowed_variants: PinField<Vec<ProviderSlug>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDetails {
    pub format: SafeText,
    pub family: SafeText,
    pub parameter_size: SafeText,
    pub quantization_level: SafeText,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicy {
    pub allow_fallbacks: bool,
    pub order: Vec<ProviderSlug>,
    pub only: Vec<ProviderSlug>,
    pub require_parameters: bool,
    pub data_collection: DataCollection,
    pub disable_model_fallback: bool,
    pub disable_provider_fallback: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCollection {
    Deny,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityChannel {
    OllamaTags,
    GeminiModelVersion,
    OpenRouterGeneration,
    GroqUnverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    #[serde(rename = "local-open-weight")]
    LocalOpenWeight,
    #[serde(rename = "free-tier")]
    FreeTier,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("pin field {field} must be absent for this target")]
    FieldMustBeAbsent { field: &'static str },
    #[error("pin field {field} is required for this target")]
    MissingRequiredField { field: &'static str },
    #[error("model details are required where the runtime reports them")]
    ModelDetailsRequired,
    #[error("fallback flags must be disabled for every pin")]
    FallbackEnabled,
    #[error("variant list contains a duplicate")]
    DuplicateVariant,
    #[error("local pin endpoint must be loopback")]
    EndpointNotLoopback,
    #[error("free-tier pin endpoint must be HTTPS")]
    EndpointNotHttps,
    #[error("Groq served identity is unverified; the profile is unavailable")]
    GroqUnverified,
    #[error("served identity channel does not match the pin's provider")]
    ServedIdentityChannelMismatch,
    #[error("route policy is required for this target")]
    RoutePolicyRequired,
    #[error("pin revision must be present and 1-based")]
    InvalidPinRevision,
    #[error("null is not the design's absent")]
    NullIsNotAbsent,
}

impl ModelPin {
    /// Validates the exact LLD §8.1 matrix (see T45 draft §4.3).
    pub fn validate(&self) -> Result<(), PinError> {
        let kind = match self.target_kind.as_ref() {
            Some(kind) => *kind,
            None => {
                return Err(PinError::MissingRequiredField {
                    field: "target_kind",
                })
            }
        };
        for field in [
            "pin_revision",
            "provider",
            "logical_model",
            "api_alias_or_tag",
            "identity_channel",
            "adapter_executable_digest",
            "adapter_version",
            "config_digest",
            "endpoint",
        ] {
            if self.field_is_absent(field) {
                return Err(PinError::MissingRequiredField { field });
            }
        }
        match self.pin_revision.as_ref() {
            Some(rev) if rev.0 >= 1 => {}
            _ => return Err(PinError::InvalidPinRevision),
        }

        let endpoint = self.endpoint.as_ref().expect("checked above");
        match kind {
            TargetKind::LocalOpenWeight => {
                for field in ["weight_digest", "runtime_version"] {
                    if self.field_is_absent(field) {
                        return Err(PinError::MissingRequiredField { field });
                    }
                }
                if !endpoint.is_loopback() {
                    return Err(PinError::EndpointNotLoopback);
                }
                if self.credential_ref.is_present() {
                    return Err(PinError::FieldMustBeAbsent {
                        field: "credential_ref",
                    });
                }
                if self.identity_channel.as_ref() != Some(&IdentityChannel::OllamaTags) {
                    return Err(PinError::ServedIdentityChannelMismatch);
                }
            }
            TargetKind::FreeTier => {
                for field in ["weight_digest", "runtime_version", "model_details"] {
                    if self.field_is_present(field) {
                        return Err(PinError::FieldMustBeAbsent { field });
                    }
                }
                if !endpoint.is_https() {
                    return Err(PinError::EndpointNotHttps);
                }
                if self.route_policy.as_ref().is_none() {
                    return Err(PinError::RoutePolicyRequired);
                }
                if self.credential_ref.as_ref().is_none() {
                    return Err(PinError::MissingRequiredField {
                        field: "credential_ref",
                    });
                }
                match self.identity_channel.as_ref() {
                    Some(
                        IdentityChannel::GeminiModelVersion | IdentityChannel::OpenRouterGeneration,
                    ) => {}
                    Some(IdentityChannel::GroqUnverified) => return Err(PinError::GroqUnverified),
                    _ => return Err(PinError::ServedIdentityChannelMismatch),
                }
            }
        }

        if let Some(route) = self.route_policy.as_ref() {
            if route.allow_fallbacks
                || !route.require_parameters
                || !route.disable_model_fallback
                || !route.disable_provider_fallback
            {
                return Err(PinError::FallbackEnabled);
            }
            if !is_sorted_unique(&route.order) || !is_sorted_unique(&route.only) {
                return Err(PinError::DuplicateVariant);
            }
        }
        if let Some(variants) = self.allowed_variants.as_ref() {
            if !is_sorted_unique(variants) {
                return Err(PinError::DuplicateVariant);
            }
        }
        Ok(())
    }

    fn field_is_absent(&self, field: &str) -> bool {
        match field {
            "pin_revision" => self.pin_revision.is_absent(),
            "target_kind" => self.target_kind.is_absent(),
            "provider" => self.provider.is_absent(),
            "logical_model" => self.logical_model.is_absent(),
            "api_alias_or_tag" => self.api_alias_or_tag.is_absent(),
            "weight_digest" => self.weight_digest.is_absent(),
            "runtime_version" => self.runtime_version.is_absent(),
            "model_details" => self.model_details.is_absent(),
            "endpoint" => self.endpoint.is_absent(),
            "route_policy" => self.route_policy.is_absent(),
            "identity_channel" => self.identity_channel.is_absent(),
            "adapter_executable_digest" => self.adapter_executable_digest.is_absent(),
            "adapter_version" => self.adapter_version.is_absent(),
            "config_digest" => self.config_digest.is_absent(),
            "credential_ref" => self.credential_ref.is_absent(),
            "allowed_variants" => self.allowed_variants.is_absent(),
            _ => true,
        }
    }

    fn field_is_present(&self, field: &str) -> bool {
        !self.field_is_absent(field)
    }
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
