//! D27 gate boundary. Phase B production is fail-closed: every Worker dispatch
//! is denied and every certificate is `Absent { PhaseBNotImplemented }`.
//!
//! `ReadinessCertificate`'s 13-check DTO is #32's scope, so S1 freezes only the
//! opaque handle and the gate/fixture boundary.

use serde::{Deserialize, Serialize};

use super::dispatch::{AnchoredInvocation, TaskBinding};
use super::primitives::{CertificateId, FingerprintDigest};

pub trait CertificateIssuer: Send + Sync {
    fn issue(
        &self,
        task: &TaskBinding,
        input_fingerprint: FingerprintDigest,
    ) -> super::primitives::BoxFuture<'_, Result<ReadinessCertificate, CertificateError>>;
}

pub trait CertificateVerifier: Send + Sync {
    fn verify(
        &self,
        certificate_id: CertificateId,
        input_fingerprint: FingerprintDigest,
    ) -> super::primitives::BoxFuture<'_, Result<CertificateVerdict, CertificateError>>;
}

pub trait WorkerDispatchGate: Send + Sync {
    fn authorize(
        &self,
        binding: &AnchoredInvocation,
    ) -> Result<WorkerAuthorization, super::adapter::DispatchDenial>;
}

pub struct WorkerAuthorization {
    pub certificate_id: CertificateId,
    pub input_fingerprint: FingerprintDigest,
}

/// Opaque handle: no public `valid` flag, no product decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessCertificate {
    certificate_id: CertificateId,
    input_fingerprint: FingerprintDigest,
    state: CertificateState,
}

impl ReadinessCertificate {
    pub fn certificate_id(&self) -> &CertificateId {
        &self.certificate_id
    }

    pub fn input_fingerprint(&self) -> FingerprintDigest {
        self.input_fingerprint
    }

    pub fn state(&self) -> CertificateState {
        self.state
    }

    /// Test-only constructor; never compiled into a release build.
    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_current(
        certificate_id: CertificateId,
        input_fingerprint: FingerprintDigest,
    ) -> Self {
        Self {
            certificate_id,
            input_fingerprint,
            state: CertificateState::Current,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateState {
    Current,
    Invalidated(CertificateInvalidReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateVerdict {
    Absent {
        reason: CertificateAbsentReason,
    },
    Invalid {
        reason: CertificateInvalidReason,
    },
    /// The only value that can authorize a Worker dispatch.
    Current {
        certificate_id: CertificateId,
        input_fingerprint: FingerprintDigest,
    },
}

impl CertificateVerdict {
    pub fn authorizes_worker(&self) -> bool {
        matches!(self, Self::Current { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateAbsentReason {
    NotIssued,
    PhaseBNotImplemented,
    StoreUnreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateInvalidReason {
    StaleFingerprint,
    Expired,
    CheckNotCurrent,
    EvidenceInvalid,
    Superseded,
    OwnerRevoked,
}

#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("readiness certificates are not implemented in Phase B")]
    PhaseBNotImplemented,
    #[error("certificate store is unreadable")]
    StoreUnreadable,
    #[error("certificate is invalid")]
    Invalid,
    #[error("certificate does not match the dispatch fingerprint")]
    FingerprintMismatch,
}

// ---------------------------------------------------------------------------
// Fail-closed production implementations (PM decision §11.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct FailClosedWorkerGate;

impl WorkerDispatchGate for FailClosedWorkerGate {
    fn authorize(
        &self,
        _binding: &AnchoredInvocation,
    ) -> Result<WorkerAuthorization, super::adapter::DispatchDenial> {
        Err(super::adapter::DispatchDenial::D27CertificateAbsent)
    }
}

#[derive(Debug, Default)]
pub struct FailClosedCertificateVerifier;

impl CertificateVerifier for FailClosedCertificateVerifier {
    fn verify(
        &self,
        _certificate_id: CertificateId,
        _input_fingerprint: FingerprintDigest,
    ) -> super::primitives::BoxFuture<'_, Result<CertificateVerdict, CertificateError>> {
        Box::pin(async {
            Ok(CertificateVerdict::Absent {
                reason: CertificateAbsentReason::PhaseBNotImplemented,
            })
        })
    }
}

#[derive(Debug, Default)]
pub struct UnavailableCertificateIssuer;

impl CertificateIssuer for UnavailableCertificateIssuer {
    fn issue(
        &self,
        _task: &TaskBinding,
        _input_fingerprint: FingerprintDigest,
    ) -> super::primitives::BoxFuture<'_, Result<ReadinessCertificate, CertificateError>> {
        Box::pin(async { Err(CertificateError::PhaseBNotImplemented) })
    }
}
