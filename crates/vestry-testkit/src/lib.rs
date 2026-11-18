//! Reusable Win32 Job-object harness for owning and proving child-process trees.
//!
//! Test-only support library for Phase B Track 2 (#15 cancellation, #24
//! kill/restart) and the B2.1 `OwnedProcess` boundary. It implements the
//! creation-time assignment the design requires (T41 §8 R4): children are
//! created **inside** a fresh Job via `PROC_THREAD_ATTRIBUTE_JOB_LIST` and
//! `CREATE_SUSPENDED`, identified while suspended, then resumed once. There is
//! no spawn-then-assign fallback.
//!
//! Every Win32 handle is owned by an RAII guard, so an error at any step
//! closes each handle exactly once (T46 finding F2). The Job guard sets
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so dropping it is last-resort
//! containment: every remaining member is killed.
//!
//! Capabilities (documented API for Track 2 consumption):
//!
//! - [`Job::process_ids`] — enumerate member PIDs;
//! - [`Job::process_identities`] / [`SpawnedChild::identity`] — capture
//!   `(pid, creation_filetime)` identities;
//! - [`Job::terminate`] — `TerminateJobObject`;
//! - [`Job::wait_empty`] — empty-proof: empty PID list **and** zero
//!   `ActiveProcesses`, never assumed;
//! - drop-without-terminate containment — [`Job`] sets kill-on-close and
//!   [`Job::open_wait_handles`] supplies wait handles for independent proof;
//! - [`ContainedTree`] — the documented spawn → identify → resume cycle.
//!
//! Windows-only. No network, model, credential or file-system access; tests
//! spawn `cmd.exe` and the local `ping` sleep utility only.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod job;

#[cfg(windows)]
pub use job::{
    ContainedTree, EmptyProof, HarnessError, Job, JobAccounting, JobAttributeList, ProcessIdentity,
    SpawnedChild, WaitHandle,
};
