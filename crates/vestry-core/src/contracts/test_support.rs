//! Test-only fixtures. Compiled only with `cfg(test)` or the `test-support`
//! feature; never present in a release build (PM decision §G.2).

use super::certificate::{
    CertificateError, CertificateVerdict, CertificateVerifier, ReadinessCertificate,
};
use super::primitives::{CertificateId, FingerprintDigest};

/// Gate-logic test double. It exercises `Current`/stale branches only; it never
/// issues a D27 certificate and must never be wired into `vestryd`.
#[derive(Debug, Default)]
pub struct FakeCertificateVerifier {
    pub current: Option<(CertificateId, FingerprintDigest)>,
}

impl CertificateVerifier for FakeCertificateVerifier {
    fn verify(
        &self,
        certificate_id: CertificateId,
        input_fingerprint: FingerprintDigest,
    ) -> super::primitives::BoxFuture<'_, Result<CertificateVerdict, CertificateError>> {
        let current = self.current.clone();
        Box::pin(async move {
            match current {
                Some((id, fingerprint))
                    if id == certificate_id && fingerprint == input_fingerprint =>
                {
                    Ok(CertificateVerdict::Current {
                        certificate_id,
                        input_fingerprint,
                    })
                }
                Some(_) => Ok(CertificateVerdict::Invalid {
                    reason: super::certificate::CertificateInvalidReason::StaleFingerprint,
                }),
                None => Ok(CertificateVerdict::Absent {
                    reason: super::certificate::CertificateAbsentReason::NotIssued,
                }),
            }
        })
    }
}

/// Test-only certificate handle; the production issuer is unavailable.
pub fn fixture_certificate(
    certificate_id: CertificateId,
    input_fingerprint: FingerprintDigest,
) -> ReadinessCertificate {
    ReadinessCertificate::fixture_current(certificate_id, input_fingerprint)
}
