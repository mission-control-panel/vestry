//! Windows process-supervision boundary: Job objects, creation-time
//! assignment and process identity (LLD §8.4; T41 §4.4).
//!
//! This is the only module permitted to use `unsafe`. S1 freezes the contract
//! only: the real spawner is B2.1 work, so this type is a typed refusal that
//! performs no process creation and never fabricates proof. The S0 Win32 Job
//! smoke probe lives in the `vestry-testkit` binary.

use crate::contracts::process::{
    BoxFuture, OwnedProcess, OwnedProcessSpawner, OwnedSpawnSpec, ProcessError,
};

#[derive(Debug, Default)]
pub struct WindowsOwnedProcessSpawner;

impl OwnedProcessSpawner for WindowsOwnedProcessSpawner {
    fn spawn(
        &self,
        _spec: OwnedSpawnSpec,
    ) -> BoxFuture<'_, Result<Box<dyn OwnedProcess>, ProcessError>> {
        Box::pin(async { Err(ProcessError::PhaseBNotImplemented) })
    }
}
