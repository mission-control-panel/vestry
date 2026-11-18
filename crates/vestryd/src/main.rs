//! Vestry daemon entrypoint — Phase B stub.
//!
//! No product behaviour exists yet. The composition root wires the fail-closed
//! D27 trio explicitly and the daemon fails closed with exit code 2 so nothing
//! that expects a working control plane can mistake this scaffold for one
//! (D48; T41 §6.0; PM decision §11.1).

use vestry_core::contracts::certificate::{
    CertificateIssuer, CertificateVerifier, FailClosedCertificateVerifier, FailClosedWorkerGate,
    UnavailableCertificateIssuer, WorkerDispatchGate,
};

/// The production composition root. Every field is the fail-closed Phase B
/// implementation: there is no configuration flag that swaps in a fixture gate.
struct CompositionRoot {
    gate: Box<dyn WorkerDispatchGate>,
    verifier: Box<dyn CertificateVerifier>,
    issuer: Box<dyn CertificateIssuer>,
}

fn composition_root() -> CompositionRoot {
    CompositionRoot {
        gate: Box::new(FailClosedWorkerGate),
        verifier: Box::new(FailClosedCertificateVerifier),
        issuer: Box::new(UnavailableCertificateIssuer),
    }
}

fn main() {
    let root = composition_root();
    // The trio is intentionally named so a release build cannot drop it.
    let _fail_closed = (&root.gate, &root.verifier, &root.issuer);
    eprintln!("vestryd: not implemented (Phase B S0)");
    std::process::exit(2);
}
