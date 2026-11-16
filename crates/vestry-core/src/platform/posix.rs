//! POSIX process-control seam (T41 §4.4, §6.2) — **fail-closed stub only**.
//!
//! Phase B implements Windows only. This stub performs no process creation and
//! returns a typed refusal; it is not a degraded implementation and never
//! fabricates a termination proof.

use crate::contracts::process::{
    BoxFuture, OwnedProcess, OwnedProcessSpawner, OwnedSpawnSpec, ProcessError,
};

#[derive(Debug, Default)]
pub struct PosixOwnedProcessSpawner;

impl OwnedProcessSpawner for PosixOwnedProcessSpawner {
    fn spawn(
        &self,
        _spec: OwnedSpawnSpec,
    ) -> BoxFuture<'_, Result<Box<dyn OwnedProcess>, ProcessError>> {
        Box::pin(async { Err(ProcessError::UnsupportedPlatform) })
    }
}
