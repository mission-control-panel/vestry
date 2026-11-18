//! C8 primitives: opaque identifiers, numeric conventions, UTC time,
//! Win32 FILETIME, digests, safe text/codes and path types.
//!
//! Design sources: LLD §3 lines 113–114, 139; LLD §14 line 520; T41 §3 C8.
//! PM decisions: T47-PM-S1-DECISIONS.md Q10, P1-13.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// Local boxed-future alias so object-safe traits need no `async_trait` dependency.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------
// C8 errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("identifier is empty")]
    Empty,
    #[error("identifier exceeds {max} bytes")]
    TooLong { max: usize },
    #[error("identifier contains a control character")]
    ControlCharacter,
    #[error("identifier contains whitespace")]
    Whitespace,
    #[error("identifier contains a character outside [A-Za-z0-9._:-]")]
    InvalidCharacter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TextError {
    #[error("text exceeds {max} bytes")]
    TooLong { max: usize },
    #[error("text contains a control character")]
    ControlCharacter,
    #[error("text is empty")]
    Empty,
    #[error("text contains a forbidden character")]
    InvalidCharacter,
    #[error("text is not absolute")]
    NotAbsolute,
    #[error("text is not relative")]
    NotRelative,
    #[error("text contains a traversal segment")]
    Traversal,
}

// ---------------------------------------------------------------------------
// SafeId and opaque ID newtypes
// ---------------------------------------------------------------------------

/// Opaque, validated identity string: 1–256 bytes ASCII `[A-Za-z0-9._:-]`.
/// No whitespace, controls, slashes or quotes (Q4/A-C8-1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeId(String);

impl SafeId {
    pub const MAX_BYTES: usize = 256;

    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(IdError::TooLong {
                max: Self::MAX_BYTES,
            });
        }
        for ch in value.chars() {
            if ch.is_ascii_whitespace() {
                return Err(IdError::Whitespace);
            }
            if ch.is_control() {
                return Err(IdError::ControlCharacter);
            }
            if !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-')) {
                return Err(IdError::InvalidCharacter);
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SafeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for SafeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SafeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(D::Error::custom)
    }
}

/// Declares an opaque ID newtype over [`SafeId`] (C8 §9.1).
#[macro_export]
macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(
            Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub $crate::contracts::primitives::SafeId);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, $crate::contracts::primitives::IdError> {
                Ok(Self($crate::contracts::primitives::SafeId::new(value)?))
            }
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

opaque_id!(ProjectId);
opaque_id!(GoalId);
opaque_id!(TaskId);
opaque_id!(RunId);
opaque_id!(AttemptId);
opaque_id!(LeaseId);
opaque_id!(AdmissionId);
opaque_id!(DispatchId);
opaque_id!(ProcessRecordId);
opaque_id!(EvidenceId);
opaque_id!(CertificateId);
opaque_id!(ManifestId);
opaque_id!(CanaryId);
opaque_id!(AnchorId);
opaque_id!(CriterionId);
opaque_id!(GateArtefactId);
opaque_id!(GateDecisionId);
opaque_id!(ClarificationId);
opaque_id!(ActionId);
opaque_id!(ApprovalId);
opaque_id!(EffectId);
opaque_id!(AttentionId);
opaque_id!(MemoryFactId);
opaque_id!(OutboxId);
opaque_id!(ReviewId);
opaque_id!(CheckResultId);
opaque_id!(CheckManifestId);
opaque_id!(SessionId);
opaque_id!(PartId);
opaque_id!(MessageId);
opaque_id!(ConditionId);
opaque_id!(ReviewIntentRef);
opaque_id!(CheckIntentRef);
opaque_id!(SnapshotRef);
opaque_id!(ModelEvidenceRef);
opaque_id!(RecoveryFindingId);
opaque_id!(StateRequestId);
opaque_id!(IdempotencyKey);
opaque_id!(OutboxKey);
opaque_id!(TrelloBoardId);
opaque_id!(TrelloListId);
opaque_id!(TrelloCardId);
opaque_id!(TrelloCommentId);

// ---------------------------------------------------------------------------
// Numeric conventions (C8 §9.2)
// ---------------------------------------------------------------------------

macro_rules! numeric_newtype {
    ($name:ident, $inner:ty) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub $inner);

        impl $name {
            pub fn get(self) -> $inner {
                self.0
            }
            pub fn next(self) -> Self {
                Self(self.0 + 1)
            }
        }
    };
}

numeric_newtype!(DaemonGeneration, u64);
numeric_newtype!(JobGeneration, u64);
numeric_newtype!(Revision, u64);
numeric_newtype!(Fence, u64);
numeric_newtype!(DispatchOrdinal, u32);
numeric_newtype!(AuditSequence, u64);
numeric_newtype!(PinRevision, u32);
numeric_newtype!(EvidenceRevision, u32);
numeric_newtype!(RedactionVersion, u32);
numeric_newtype!(PolicyRevision, u64);

impl Fence {
    /// Initial fence value (`Fence(1)`), Q10/A-C8-2. Strictly monotonic per
    /// attempt/lease and never reused; there is deliberately no `Default`.
    pub const INITIAL: Fence = Fence(1);
}

impl Revision {
    /// Initial aggregate revision (`Revision(0)`), Q10.
    pub const INITIAL: Revision = Revision(0);
}

impl AuditSequence {
    /// First audit event is 1-based and contiguous (C5 rule 10).
    pub const FIRST: AuditSequence = AuditSequence(1);
}

impl DispatchOrdinal {
    pub const FIRST: DispatchOrdinal = DispatchOrdinal(1);
}

impl PinRevision {
    pub const FIRST: PinRevision = PinRevision(1);
}

impl RedactionVersion {
    pub const V1: RedactionVersion = RedactionVersion(1);
}

// ---------------------------------------------------------------------------
// Time (C8 §9.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UtcMillis(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CreationFiletime(pub u64);

impl CreationFiletime {
    /// Edge-only human-readable conversion: `unix_ms = ft / 10_000 - epoch_delta`.
    /// Lossy in sub-millisecond precision and never stored back (Q10).
    pub fn unix_ms(self) -> i64 {
        (self.0 as u128 / 10_000) as i64 - 11_644_473_600_000
    }
}

// ---------------------------------------------------------------------------
// Digests (C8 §9.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub const ZERO: Hash32 = Hash32([0u8; 32]);

    pub fn from_hex(text: &str) -> Result<Self, TextError> {
        let bytes = decode_hex(text, 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }

    pub fn is_zero(self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_hex(&raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest {
    pub bytes: Hash32,
}

impl Sha256Digest {
    pub fn digest(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hasher.finalize());
        Self {
            bytes: Hash32(bytes),
        }
    }

    pub fn from_hex(text: &str) -> Result<Self, TextError> {
        Ok(Self {
            bytes: Hash32::from_hex(text)?,
        })
    }

    pub fn to_hex(self) -> String {
        self.bytes.to_hex()
    }
}

impl From<Hash32> for Sha256Digest {
    fn from(hash: Hash32) -> Self {
        Self { bytes: hash }
    }
}

impl std::fmt::Display for GitSha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "git:{}", self.to_hex())
    }
}

impl std::fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let hex = raw
            .strip_prefix("sha256:")
            .ok_or_else(|| D::Error::custom("digest must carry the sha256: prefix"))?;
        Self::from_hex(hex).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GitSha(pub [u8; 20]);

impl GitSha {
    pub fn from_hex(text: &str) -> Result<Self, TextError> {
        let bytes = decode_hex(text, 20)?;
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

impl Serialize for GitSha {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("git:{}", self.to_hex()))
    }
}

impl<'de> Deserialize<'de> for GitSha {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let hex = raw
            .strip_prefix("git:")
            .ok_or_else(|| D::Error::custom("git sha must carry the git: prefix"))?;
        Self::from_hex(hex).map_err(D::Error::custom)
    }
}

macro_rules! digest_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Sha256Digest);
    };
}

digest_newtype!(FingerprintDigest);
digest_newtype!(RouteFingerprint);
digest_newtype!(EnvironmentFingerprint);

fn decode_hex(text: &str, expected_bytes: usize) -> Result<Vec<u8>, TextError> {
    if text.len() != expected_bytes * 2 {
        return Err(TextError::TooLong {
            max: expected_bytes * 2,
        });
    }
    let mut out = Vec::with_capacity(expected_bytes);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or(TextError::InvalidCharacter)?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or(TextError::InvalidCharacter)?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Safe text, codes and paths (C8 §9.5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SafeText(String);

impl SafeText {
    pub const MAX_BYTES: usize = 4096;

    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        if value.len() > Self::MAX_BYTES {
            return Err(TextError::TooLong {
                max: Self::MAX_BYTES,
            });
        }
        for ch in value.chars() {
            if ch.is_control() || ch == '\u{007f}' {
                return Err(TextError::ControlCharacter);
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SafeText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for SafeText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SafeText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SafeCode(String);

impl SafeCode {
    pub const MAX_BYTES: usize = 128;

    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TextError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(TextError::TooLong {
                max: Self::MAX_BYTES,
            });
        }
        for ch in value.chars() {
            if !(ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || matches!(ch, '.' | '_' | ':' | '-'))
            {
                return Err(TextError::InvalidCharacter);
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SafeCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for SafeCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SafeCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(D::Error::custom)
    }
}

/// Declares a validated text newtype over [`SafeText`].
#[macro_export]
macro_rules! safe_text_newtype {
    ($name:ident) => {
        #[derive(
            Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub $crate::contracts::primitives::SafeText);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, $crate::contracts::primitives::TextError> {
                let text = $crate::contracts::primitives::SafeText::new(value)?;
                if text.as_str().is_empty() {
                    return Err($crate::contracts::primitives::TextError::Empty);
                }
                Ok(Self(text))
            }
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

impl std::str::FromStr for WindowsAbsolutePath {
    type Err = TextError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

fn validate_no_control(text: &str) -> Result<(), TextError> {
    for ch in text.chars() {
        if ch.is_control() || ch == '\u{007f}' {
            return Err(TextError::ControlCharacter);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WindowsAbsolutePath(String);

impl WindowsAbsolutePath {
    pub const MAX_BYTES: usize = 32767;

    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TextError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(TextError::TooLong {
                max: Self::MAX_BYTES,
            });
        }
        validate_no_control(&value)?;
        // Validation is Windows-semantic by contract; the workspace builds on Windows.
        let path = std::path::Path::new(&value);
        let has_drive = value.len() >= 3
            && value.as_bytes()[1] == b':'
            && value.as_bytes()[0].is_ascii_alphabetic();
        let unc = value.starts_with(r"\\");
        if !(path.is_absolute() || has_drive || unc) {
            return Err(TextError::NotAbsolute);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WindowsAbsolutePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SafeRelativePath(String);

impl SafeRelativePath {
    pub const MAX_BYTES: usize = 4096;

    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TextError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(TextError::TooLong {
                max: Self::MAX_BYTES,
            });
        }
        validate_no_control(&value)?;
        if value.starts_with('/') || value.starts_with('\\') || value.contains(':') {
            return Err(TextError::NotRelative);
        }
        if value.contains('\\') {
            return Err(TextError::InvalidCharacter);
        }
        for segment in value.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(TextError::Traversal);
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SafeRelativePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScratchScope(String);

impl ScratchScope {
    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TextError::Empty);
        }
        if value.len() > 4096 {
            return Err(TextError::TooLong { max: 4096 });
        }
        validate_no_control(&value)?;
        for segment in value.split(['/', '\\']) {
            if segment == ".." {
                return Err(TextError::Traversal);
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ScratchScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BranchName(String);

impl BranchName {
    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TextError::Empty);
        }
        if value.len() > 255 {
            return Err(TextError::TooLong { max: 255 });
        }
        if value.starts_with('-') || value.contains("..") {
            return Err(TextError::InvalidCharacter);
        }
        for ch in value.chars() {
            if !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '/' | '-')) {
                return Err(TextError::InvalidCharacter);
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BranchName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
