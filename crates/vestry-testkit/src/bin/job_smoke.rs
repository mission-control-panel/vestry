//! Win32 creation-time Job assignment smoke probe (Phase B S0, T43).
//!
//! This binary proves, on THIS host, that the design's process-containment
//! primitive works: a child created **inside** a fresh Job object with
//! `PROC_THREAD_ATTRIBUTE_JOB_LIST` and `CREATE_SUSPENDED`, identified while
//! suspended, then terminated through the Job, leaving an empty process list
//! and zero active accounting. There is deliberately **no spawn-then-assign
//! fallback** — the design forbids it (T41 §8 R4).
//!
//! The Win32 mechanics live in the reusable [`vestry_testkit`] harness; this
//! binary keeps the S0 step-by-step stdout contract and exit codes and prints
//! each step as it is performed. Every handle is owned by an RAII guard, so
//! an error at any step closes everything exactly once (T46 F2).
//!
//! It is a test-only smoke probe, not the production `OwnedProcess` (B2.1).
//! It makes no network, model or credential access.
//!
//! Exit codes: 0 = PASS. Non-zero identifies the failing step; every failure
//! prints the step and the exact Win32 error (HRESULT and the low 16 bits).

#![deny(unsafe_op_in_unsafe_fn)]

use std::time::Duration;

use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

use vestry_testkit::{HarnessError, Job};

struct Fail {
    step: &'static str,
    exit_code: i32,
    detail: String,
}

impl Fail {
    fn assertion(step: &'static str, exit_code: i32, detail: impl Into<String>) -> Self {
        Self {
            step,
            exit_code,
            detail: detail.into(),
        }
    }

    fn harness(step: &'static str, exit_code: i32, error: HarnessError) -> Self {
        Self {
            step,
            exit_code,
            detail: error.detail(),
        }
    }
}

fn run() -> Result<(), Fail> {
    // Step 1: fresh unnamed Job. A null security descriptor gives a
    // non-inheritable handle. The RAII guard closes it on every path.
    let job = Job::create_unconfigured().map_err(|error| Fail::harness("create_job", 2, error))?;
    println!("step=create_job ok");

    // Step 2: KILL_ON_JOB_CLOSE, then read the setting back.
    job.set_kill_on_job_close()
        .map_err(|error| Fail::harness("set_kill_on_job_close", 3, error))?;
    println!("step=set_kill_on_job_close ok");

    let flags = job
        .kill_on_close_flags()
        .map_err(|error| Fail::harness("readback_kill_on_job_close", 4, error))?;
    if flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 != JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 {
        return Err(Fail::assertion(
            "readback_kill_on_job_close",
            4,
            format!(
                "expected flag {} present, read back limit_flags=0x{flags:08X}",
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0
            ),
        ));
    }
    println!("step=readback_kill_on_job_close ok limit_flags=0x{flags:08X} kill_on_job_close=1");

    // Step 3: thread attribute list holding the Job handle.
    let attributes = job
        .attribute_list()
        .map_err(|error| Fail::harness("init_attribute_list", 5, error))?;
    println!(
        "step=attribute_list ok attribute=PROC_THREAD_ATTRIBUTE_JOB_LIST size={}",
        attributes.size()
    );

    // Step 4: create the child suspended, assigned to the Job at creation.
    let child = job
        .spawn_suspended_with(&attributes, "cmd.exe /c exit 0")
        .map_err(|error| Fail::harness("create_process_suspended", 6, error))?;
    println!(
        "step=create_process_suspended ok root_pid={} thread_id={}",
        child.pid(),
        child.thread_id()
    );

    // Step 5: identity while suspended — creation FILETIME, captured through
    // the process handle before the thread is resumed.
    let identity = child
        .identity()
        .map_err(|error| Fail::harness("process_identity", 7, error))?;
    println!(
        "step=process_identity ok root_pid={} creation_filetime={}",
        identity.pid, identity.creation_filetime
    );

    let suspended_ids = job
        .process_ids()
        .map_err(|error| Fail::harness("enumerate_suspended", 8, error))?;
    if suspended_ids != vec![identity.pid] {
        return Err(Fail::assertion(
            "enumerate_suspended",
            8,
            format!(
                "expected exactly root pid {} in Job while suspended, found {suspended_ids:?}",
                identity.pid
            ),
        ));
    }
    println!("step=enumerate_suspended ok count=1 pids={suspended_ids:?}");

    // Step 6: resume once.
    let previous_suspend_count = child
        .resume()
        .map_err(|error| Fail::harness("resume_thread", 9, error))?;
    println!("step=resume_thread ok previous_suspend_count={previous_suspend_count}");

    // Step 7: terminate through the Job, not through the child handle.
    job.terminate(1)
        .map_err(|error| Fail::harness("terminate_job", 10, error))?;
    println!("step=terminate_job ok exit_code=1");

    // Step 8: verify empty process list and zero active accounting.
    let proof = job
        .wait_empty(Duration::from_secs(5))
        .map_err(|error| Fail::harness("job_empty", 11, error))?;
    println!(
        "step=job_empty ok pids=[] active_processes=0 total_processes={} total_terminated={} waited_ms={}",
        proof.accounting.total_processes,
        proof.accounting.total_terminated_processes,
        proof.waited.as_millis()
    );
    println!("PASS job_smoke");
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => std::process::exit(0),
        Err(fail) => {
            eprintln!("FAIL step={} detail={}", fail.step, fail.detail);
            std::process::exit(fail.exit_code);
        }
    }
}
