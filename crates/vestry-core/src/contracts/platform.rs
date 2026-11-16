//! D1 single-instance lock contract and platform selection (PM decisions D1/D3).

use super::primitives::{DaemonGeneration, WindowsAbsolutePath};

pub trait InstanceLock: Send {
    fn path(&self) -> &WindowsAbsolutePath;
    fn release(self: Box<Self>) -> Result<(), InstanceLockError>;
}

pub trait InstanceLockProvider: Send + Sync {
    fn try_acquire(
        &self,
        path: &WindowsAbsolutePath,
    ) -> Result<Box<dyn InstanceLock>, InstanceLockError>;
}

#[derive(Debug, thiserror::Error)]
pub enum InstanceLockError {
    #[error("another daemon holds the lock at {path}")]
    AlreadyRunning { path: WindowsAbsolutePath },
    #[error("cannot open lock file {path}: Win32 {code}")]
    OpenFailed {
        path: WindowsAbsolutePath,
        code: u32,
    },
    #[error("LockFileEx failed: Win32 {code}")]
    LockFailed { code: u32 },
    #[error("UnlockFileEx failed: Win32 {code}")]
    UnlockFailed { code: u32 },
    #[error("lock path is not a safe absolute path")]
    UnsafePath,
    #[error("single-instance lock is unsupported on this platform")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerationOwnership {
    Acquired {
        generation: DaemonGeneration,
        previous_generation: Option<DaemonGeneration>,
        previous_clean_shutdown: Option<bool>,
    },
    AlreadyRunning {
        path: WindowsAbsolutePath,
    },
    OwnershipConflict {
        reason: OwnershipConflictReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipConflictReason {
    SchemaUnknown,
    SchemaNewer,
    AuditChainUnavailable,
    DatabaseUnreadable,
}

impl GenerationOwnership {
    /// Only `Acquired` may proceed to writer/Doctor startup.
    pub fn permits_startup(&self) -> bool {
        matches!(self, Self::Acquired { .. })
    }
}

#[cfg(windows)]
pub type PlatformSpawner = crate::platform::windows::WindowsOwnedProcessSpawner;

#[cfg(not(windows))]
pub type PlatformSpawner = crate::platform::posix::PosixOwnedProcessSpawner;
