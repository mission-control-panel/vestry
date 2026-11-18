//! Win32 Job-object harness implementation.
//!
//! The Win32 surface is confined to this module. Every handle is closed by
//! [`OwnedHandle`]'s `Drop`; the thread-attribute list is released by
//! [`JobAttributeList`]'s `Drop`. Unsafe blocks are limited to the documented
//! FFI calls and each one states its invariant.

use std::ffi::c_void;
use std::fmt;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

use windows::core::{Error, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectBasicAccountingInformation, JobObjectBasicProcessIdList,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetProcessTimes,
    InitializeProcThreadAttributeList, OpenProcess, ResumeThread, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROC_THREAD_ATTRIBUTE_JOB_LIST, STARTUPINFOEXW,
};

/// Maximum member processes enumerated in one query.
const MAX_JOB_PROCESSES: usize = 256;

/// Poll interval while waiting for Job membership to drain.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Error from a harness operation: the failing operation plus the Win32 cause
/// or the assertion that did not hold.
#[derive(Debug)]
pub struct HarnessError {
    op: &'static str,
    kind: ErrorKind,
}

#[derive(Debug)]
enum ErrorKind {
    Win32(Error),
    Assertion(String),
}

impl HarnessError {
    fn win32(op: &'static str, error: Error) -> Self {
        Self {
            op,
            kind: ErrorKind::Win32(error),
        }
    }

    fn assertion(op: &'static str, detail: impl Into<String>) -> Self {
        Self {
            op,
            kind: ErrorKind::Assertion(detail.into()),
        }
    }

    /// The failing operation, e.g. `create_process_suspended`.
    pub fn op(&self) -> &'static str {
        self.op
    }

    /// Win32 detail in the record format used by the S0 probe:
    /// `hresult=0x… win32_error=… message=…`.
    pub fn detail(&self) -> String {
        match &self.kind {
            ErrorKind::Win32(error) => {
                let hresult = error.code().0 as u32;
                let win32 = hresult & 0xFFFF;
                format!("hresult=0x{hresult:08X} win32_error={win32} message={error}")
            }
            ErrorKind::Assertion(detail) => detail.clone(),
        }
    }
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.op, self.detail())
    }
}

impl std::error::Error for HarnessError {}

/// Owns one Win32 handle and closes it exactly once.
#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this guard and closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// `(pid, creation FILETIME)` identity. A PID alone is never identity; the
/// creation time distinguishes a reused PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// The raw 64-bit `FILETIME` (100 ns ticks since 1601) from
    /// `GetProcessTimes`; compare values, do not reinterpret as a calendar time.
    pub creation_filetime: u64,
}

/// Basic accounting read back from the Job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobAccounting {
    pub active_processes: u32,
    pub total_processes: u32,
    pub total_terminated_processes: u32,
}

/// The proof that a Job is empty: the PID list is empty **and** the Job
/// reports zero active processes, sampled together after termination.
#[derive(Debug, Clone)]
pub struct EmptyProof {
    pub process_ids: Vec<u32>,
    pub accounting: JobAccounting,
    pub waited: Duration,
}

/// A borrowed wait handle for one Job member (opened with `SYNCHRONIZE`).
/// Used to prove, independently of the Job handle, that a member exited.
#[derive(Debug)]
pub struct WaitHandle(OwnedHandle);

impl WaitHandle {
    /// Wait up to `timeout` for the process to exit. `Ok(true)` means
    /// signalled (exited), `Ok(false)` means the timeout elapsed.
    pub fn wait(&self, timeout: Duration) -> Result<bool, HarnessError> {
        let result = unsafe { WaitForSingleObject(self.0 .0, timeout_millis(timeout)) };
        if result == WAIT_OBJECT_0 {
            Ok(true)
        } else if result == WAIT_TIMEOUT {
            Ok(false)
        } else {
            Err(HarnessError::win32("wait_process", Error::from_thread()))
        }
    }
}

/// A fresh unnamed Job with `KILL_ON_JOB_CLOSE` set and verified. Dropping it
/// closes the handle, which kills every remaining member as last-resort
/// containment.
#[derive(Debug)]
pub struct Job {
    handle: OwnedHandle,
}

impl Job {
    /// Creates a Job and sets + verifies `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    pub fn create() -> Result<Self, HarnessError> {
        let job = Self::create_unconfigured()?;
        job.set_kill_on_job_close()?;
        let flags = job.kill_on_close_flags()?;
        if flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 != JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 {
            return Err(HarnessError::assertion(
                "readback_kill_on_job_close",
                format!(
                    "expected flag {} present, read back limit_flags=0x{flags:08X}",
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0
                ),
            ));
        }
        Ok(job)
    }

    /// Creates the Job without configuring limits. Only for probes that must
    /// report `create_job`, `set_kill_on_job_close` and the read-back as
    /// separate steps; production/track-2 users call [`Job::create`].
    pub fn create_unconfigured() -> Result<Self, HarnessError> {
        // SAFETY: standard unnamed Job creation with a null security
        // descriptor gives a non-inheritable handle.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|error| HarnessError::win32("create_job", error))?;
        Ok(Self {
            handle: OwnedHandle(handle),
        })
    }

    /// Sets `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (last-resort containment).
    pub fn set_kill_on_job_close(&self) -> Result<(), HarnessError> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the struct and size match JobObjectExtendedLimitInformation.
        unsafe {
            SetInformationJobObject(
                self.handle.0,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|error| HarnessError::win32("set_kill_on_job_close", error))
    }

    /// Reads back the extended limit flags.
    pub fn kill_on_close_flags(&self) -> Result<u32, HarnessError> {
        let mut readback = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: the struct is the documented size for this information class.
        unsafe {
            QueryInformationJobObject(
                Some(self.handle.0),
                JobObjectExtendedLimitInformation,
                &mut readback as *mut _ as *mut c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                None,
            )
        }
        .map_err(|error| HarnessError::win32("readback_kill_on_job_close", error))?;
        Ok(readback.BasicLimitInformation.LimitFlags.0)
    }

    /// Creates a thread-attribute list carrying this Job's handle
    /// (`PROC_THREAD_ATTRIBUTE_JOB_LIST`) for creation-time assignment.
    pub fn attribute_list(&self) -> Result<JobAttributeList, HarnessError> {
        let mut size: usize = 0;
        // SAFETY: a null list is the documented size query; it is expected to
        // fail with ERROR_INSUFFICIENT_BUFFER and set `size`.
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) };
        if size == 0 {
            return Err(HarnessError::assertion(
                "init_attribute_list",
                "size query returned zero",
            ));
        }
        // The list stores internal pointers, so its storage must be suitably
        // aligned. Vec<u128> guarantees 16-byte alignment.
        let words = size.div_ceil(16);
        let mut storage: Vec<u128> = vec![0; words];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr() as *mut c_void);
        // SAFETY: storage is at least `size` bytes and the list is initialised
        // exactly once with one attribute.
        unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut size) }
            .map_err(|error| HarnessError::win32("init_attribute_list", error))?;

        let attributes = JobAttributeList {
            _storage: storage,
            list,
            size,
        };
        // SAFETY: the list is initialised; `self.handle.0` is a live HANDLE
        // and `size_of::<HANDLE>()` is the required value size.
        unsafe {
            UpdateProcThreadAttribute(
                attributes.list,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                Some(&self.handle.0 as *const HANDLE as *const c_void),
                size_of::<HANDLE>(),
                None,
                None,
            )
        }
        .map_err(|error| HarnessError::win32("update_job_list_attribute", error))?;
        Ok(attributes)
    }

    /// Spawns `command_line` suspended **inside** this Job at creation time.
    /// The caller must capture [`SpawnedChild::identity`] before
    /// [`SpawnedChild::resume`].
    pub fn spawn_suspended(&self, command_line: &str) -> Result<SpawnedChild, HarnessError> {
        let attributes = self.attribute_list()?;
        self.spawn_suspended_with(&attributes, command_line)
    }

    /// Spawns `command_line` suspended inside this Job using a pre-built
    /// attribute list.
    pub fn spawn_suspended_with(
        &self,
        attributes: &JobAttributeList,
        command_line: &str,
    ) -> Result<SpawnedChild, HarnessError> {
        let mut command_line: Vec<u16> = std::ffi::OsStr::new(command_line)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.list;
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: `startup` is a live STARTUPINFOEXW with the attribute list
        // attached, the command line is a mutable NUL-terminated UTF-16
        // buffer, and the process information struct is writable.
        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(command_line.as_mut_ptr())),
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                None,
                PCWSTR::null(),
                &startup.StartupInfo as *const _,
                &mut process,
            )
        }
        .map_err(|error| HarnessError::win32("create_process_suspended", error))?;
        Ok(SpawnedChild {
            process: OwnedHandle(process.hProcess),
            thread: OwnedHandle(process.hThread),
            pid: process.dwProcessId,
            thread_id: process.dwThreadId,
        })
    }

    /// Enumerates member PIDs.
    pub fn process_ids(&self) -> Result<Vec<u32>, HarnessError> {
        self.process_ids_raw()
            .map_err(|error| HarnessError::win32("enumerate_job_processes", error))
    }

    fn process_ids_raw(&self) -> Result<Vec<u32>, Error> {
        // JOBOBJECT_BASIC_PROCESS_ID_LIST is variable length: two u32 counters
        // followed by `NumberOfProcessIdsInList` usize PIDs starting at
        // `offset_of!(..., ProcessIdList)` (8 bytes in, not 16).
        let mut buffer: Vec<u64> = vec![0; 1 + MAX_JOB_PROCESSES];
        let capacity_bytes = (buffer.len() * size_of::<u64>()) as u32;
        let header = buffer.as_mut_ptr() as *mut JOBOBJECT_BASIC_PROCESS_ID_LIST;
        // SAFETY: `buffer` is 8-byte aligned and `capacity_bytes` covers the
        // two counters plus MAX_JOB_PROCESSES entries; `header` points into
        // that live allocation.
        unsafe {
            QueryInformationJobObject(
                Some(self.handle.0),
                JobObjectBasicProcessIdList,
                header as *mut c_void,
                capacity_bytes,
                None,
            )
        }?;
        // SAFETY: the API filled the header region of the live buffer above.
        let count = unsafe { (*header).NumberOfProcessIdsInList as usize };
        if count > MAX_JOB_PROCESSES {
            return Err(Error::new(
                windows::Win32::Foundation::E_UNEXPECTED,
                format!("reported {count} ids, exceeding capacity {MAX_JOB_PROCESSES}"),
            ));
        }
        // SAFETY: PIDs begin at `offset_of!(ProcessIdList)` inside the same
        // live buffer and `count` entries were written there.
        Ok(unsafe {
            let base = (header as *const u8)
                .add(offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList))
                as *const usize;
            std::slice::from_raw_parts(base, count)
                .iter()
                .map(|id| *id as u32)
                .collect()
        })
    }

    /// Reads basic accounting (`ActiveProcesses`, totals).
    pub fn accounting(&self) -> Result<JobAccounting, HarnessError> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: the struct is the documented size for this class.
        unsafe {
            QueryInformationJobObject(
                Some(self.handle.0),
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut c_void,
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                None,
            )
        }
        .map_err(|error| HarnessError::win32("accounting", error))?;
        Ok(JobAccounting {
            active_processes: info.ActiveProcesses,
            total_processes: info.TotalProcesses,
            total_terminated_processes: info.TotalTerminatedProcesses,
        })
    }

    /// Captures `(pid, creation FILETIME)` for every current member.
    ///
    /// A member that exits between enumeration and the identity query makes
    /// this return an error; call it while the tree is known to be alive.
    pub fn process_identities(&self) -> Result<Vec<ProcessIdentity>, HarnessError> {
        let mut identities = Vec::new();
        for pid in self.process_ids()? {
            // SAFETY: OpenProcess returns an owned handle on success.
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
                .map_err(|error| HarnessError::win32("open_process_for_identity", error))?;
            let handle = OwnedHandle(handle);
            identities.push(identity_from_handle(handle.0, pid)?);
        }
        Ok(identities)
    }

    /// Waits until at least `min` members exist, then returns their
    /// identities. Used to observe a grandchild before acting on the tree.
    pub fn wait_for_process_count(
        &self,
        min: usize,
        timeout: Duration,
    ) -> Result<Vec<ProcessIdentity>, HarnessError> {
        let started = Instant::now();
        loop {
            if self.process_ids()?.len() >= min {
                return self.process_identities();
            }
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(HarnessError::assertion(
                    "wait_for_process_count",
                    format!(
                        "fewer than {min} job members after {} ms",
                        elapsed.as_millis()
                    ),
                ));
            }
            std::thread::sleep(POLL_INTERVAL.min(timeout - elapsed));
        }
    }

    /// Terminates every member through `TerminateJobObject`.
    pub fn terminate(&self, exit_code: u32) -> Result<(), HarnessError> {
        // SAFETY: the Job handle is live; the exit code is arbitrary.
        unsafe { TerminateJobObject(self.handle.0, exit_code) }
            .map_err(|error| HarnessError::win32("terminate_job", error))
    }

    /// Empty-proof: waits until the PID list is empty **and** accounting
    /// reports zero active processes. Returns the proof or an assertion error
    /// describing the remaining members.
    ///
    /// `total_terminated` is intentionally not asserted: it may legitimately
    /// be 0 for harmless children (T46 observation).
    pub fn wait_empty(&self, timeout: Duration) -> Result<EmptyProof, HarnessError> {
        let started = Instant::now();
        loop {
            let accounting = self.accounting()?;
            let process_ids = self.process_ids()?;
            if process_ids.is_empty() && accounting.active_processes == 0 {
                return Ok(EmptyProof {
                    process_ids,
                    accounting,
                    waited: started.elapsed(),
                });
            }
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(HarnessError::assertion(
                    "wait_empty",
                    format!(
                        "job not empty after termination: pids={process_ids:?} active_processes={} waited_ms={}",
                        accounting.active_processes,
                        elapsed.as_millis()
                    ),
                ));
            }
            std::thread::sleep(POLL_INTERVAL.min(timeout - elapsed));
        }
    }

    /// Opens one synchronisation handle per current member. Hold these,
    /// drop the Job, then wait on each handle to prove that kill-on-close
    /// actually terminated every member.
    pub fn open_wait_handles(&self) -> Result<Vec<WaitHandle>, HarnessError> {
        let mut handles = Vec::new();
        for pid in self.process_ids()? {
            // SAFETY: OpenProcess returns an owned handle on success.
            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }
                .map_err(|error| HarnessError::win32("open_process_wait", error))?;
            handles.push(WaitHandle(OwnedHandle(handle)));
        }
        Ok(handles)
    }
}

/// Owns the initialised thread-attribute list and deletes it exactly once,
/// before its backing storage is released.
#[derive(Debug)]
pub struct JobAttributeList {
    _storage: Vec<u128>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    size: usize,
}

impl JobAttributeList {
    /// The size, in bytes, of the initialised attribute list.
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for JobAttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialised by InitializeProcThreadAttributeList
        // and is deleted exactly once. Drop runs before `_storage` is released.
        unsafe { DeleteProcThreadAttributeList(self.list) }
    }
}

/// A process created suspended inside its Job. Both handles close on drop.
#[derive(Debug)]
pub struct SpawnedChild {
    process: OwnedHandle,
    thread: OwnedHandle,
    pid: u32,
    thread_id: u32,
}

impl SpawnedChild {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Captures the identity while the process is still suspended.
    pub fn identity(&self) -> Result<ProcessIdentity, HarnessError> {
        identity_from_handle(self.process.0, self.pid)
    }

    /// Resumes the primary thread once; returns the previous suspend count.
    pub fn resume(&self) -> Result<u32, HarnessError> {
        // SAFETY: the thread handle is live and was created suspended.
        let previous = unsafe { ResumeThread(self.thread.0) };
        if previous == u32::MAX {
            Err(HarnessError::win32("resume_thread", Error::from_thread()))
        } else {
            Ok(previous)
        }
    }

    /// Waits up to `timeout` for the root process to exit.
    pub fn wait_exit(&self, timeout: Duration) -> Result<bool, HarnessError> {
        let result = unsafe { WaitForSingleObject(self.process.0, timeout_millis(timeout)) };
        if result == WAIT_OBJECT_0 {
            Ok(true)
        } else if result == WAIT_TIMEOUT {
            Ok(false)
        } else {
            Err(HarnessError::win32("wait_root", Error::from_thread()))
        }
    }
}

/// A fresh Job containing a tree spawned suspended at creation time.
///
/// [`ContainedTree::spawn`] is the documented cycle: create the Job (with
/// kill-on-close verified), spawn the root suspended inside it, capture the
/// root identity, then the caller [`SpawnedChild::resume`]s once. Dropping
/// the tree closes the Job, which kills any remaining members.
#[derive(Debug)]
pub struct ContainedTree {
    job: Job,
    root: SpawnedChild,
    root_identity: ProcessIdentity,
}

impl ContainedTree {
    pub fn spawn(command_line: &str) -> Result<Self, HarnessError> {
        let job = Job::create()?;
        let root = job.spawn_suspended(command_line)?;
        let root_identity = root.identity()?;
        Ok(Self {
            job,
            root,
            root_identity,
        })
    }

    pub fn job(&self) -> &Job {
        &self.job
    }

    pub fn root(&self) -> &SpawnedChild {
        &self.root
    }

    /// The root identity captured while the root was suspended.
    pub fn root_identity(&self) -> ProcessIdentity {
        self.root_identity
    }
}

fn identity_from_handle(handle: HANDLE, pid: u32) -> Result<ProcessIdentity, HarnessError> {
    let mut creation = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();
    // SAFETY: the handle is live with query access; four FILETIME out-pointers.
    unsafe {
        GetProcessTimes(
            handle,
            &mut creation,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
    }
    .map_err(|error| HarnessError::win32("process_identity", error))?;
    let creation_filetime =
        ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    Ok(ProcessIdentity {
        pid,
        creation_filetime,
    })
}

fn timeout_millis(timeout: Duration) -> u32 {
    let millis = timeout.as_millis();
    if millis >= u32::MAX as u128 {
        u32::MAX
    } else {
        millis as u32
    }
}
