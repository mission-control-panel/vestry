//! Windows-only behavioural tests for the reusable child-tree Job harness.
//!
//! Model-free and network-free: the tree is `cmd.exe` plus the local `ping`
//! sleep utility. Each test asserts on the empty-proof (empty PID list and
//! zero active accounting), never on `total_terminated` (T46 observation).

#![cfg(windows)]

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use vestry_testkit::{ContainedTree, Job};

/// Root `cmd.exe` that itself spawns a grandchild `cmd.exe`, which runs a
/// local `ping` sleep. All three levels must land in the Job at creation.
const TREE_COMMAND: &str = "cmd.exe /c start /b /wait cmd.exe /c ping -n 30 127.0.0.1 >nul 2>&1";

const TREE_TIMEOUT: Duration = Duration::from_secs(15);
const EMPTY_TIMEOUT: Duration = Duration::from_secs(10);

/// Kills an outside-process child even if an assertion panics.
struct ChildKiller(Child);

impl Drop for ChildKiller {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn grandchild_tree_terminates_and_proves_empty() {
    let tree = ContainedTree::spawn(TREE_COMMAND).expect("spawn contained tree");
    assert_eq!(
        tree.root_identity().pid,
        tree.root().pid(),
        "root identity must be captured while suspended"
    );
    assert_ne!(
        tree.root_identity().creation_filetime,
        0,
        "creation FILETIME must be recorded"
    );
    assert_eq!(
        tree.root().resume().expect("resume root"),
        1,
        "root must have been created suspended exactly once"
    );

    let members = tree
        .job()
        .wait_for_process_count(2, TREE_TIMEOUT)
        .expect("grandchild must join the Job");
    assert!(
        members.len() >= 2,
        "expected root plus at least one grandchild, found {members:?}"
    );
    assert!(
        members.iter().any(|m| m.pid == tree.root().pid()),
        "root must be among the Job members: {members:?}"
    );

    tree.job().terminate(1).expect("terminate job");
    let proof = tree
        .job()
        .wait_empty(EMPTY_TIMEOUT)
        .expect("job must drain after termination");
    assert!(proof.process_ids.is_empty(), "pids={:?}", proof.process_ids);
    assert_eq!(proof.accounting.active_processes, 0);
}

#[test]
fn non_owned_process_survives_job_termination() {
    let outside = Command::new("cmd.exe")
        .args(["/c", "ping", "-n", "30", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn non-owned process");
    let mut outside = ChildKiller(outside);

    // Let it get scheduled; it lives outside every fresh Job this test makes.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        outside
            .0
            .try_wait()
            .expect("poll outside process")
            .is_none(),
        "non-owned process exited before the test began"
    );

    let tree = ContainedTree::spawn(TREE_COMMAND).expect("spawn contained tree");
    tree.root().resume().expect("resume root");
    tree.job()
        .wait_for_process_count(2, TREE_TIMEOUT)
        .expect("grandchild must join the Job");
    tree.job().terminate(1).expect("terminate job");
    let proof = tree
        .job()
        .wait_empty(EMPTY_TIMEOUT)
        .expect("job must drain after termination");
    assert_eq!(proof.accounting.active_processes, 0);

    assert!(
        outside
            .0
            .try_wait()
            .expect("poll outside process")
            .is_none(),
        "terminating the owned Job killed a non-owned process"
    );
    outside.0.kill().expect("kill outside process");
    outside.0.wait().expect("reap outside process");
}

#[test]
fn drop_without_terminate_contains_tree() {
    let tree = ContainedTree::spawn(TREE_COMMAND).expect("spawn contained tree");
    tree.root().resume().expect("resume root");
    let members = tree
        .job()
        .wait_for_process_count(2, TREE_TIMEOUT)
        .expect("grandchild must join the Job");
    assert!(members.len() >= 2, "members={members:?}");

    let wait_handles = tree
        .job()
        .open_wait_handles()
        .expect("open synchronisation handles");
    assert_eq!(
        wait_handles.len(),
        members.len(),
        "one wait handle per member"
    );

    // No explicit terminate: closing the Job must kill every member.
    drop(tree);
    for handle in wait_handles {
        assert!(
            handle.wait(EMPTY_TIMEOUT).expect("wait for member exit"),
            "a Job member survived dropping the Job"
        );
    }
}

#[test]
fn twenty_spawn_terminate_cycles_are_stable() {
    for cycle in 0..20 {
        let tree = ContainedTree::spawn(TREE_COMMAND).expect("spawn contained tree");
        tree.root().resume().expect("resume root");
        tree.job()
            .wait_for_process_count(2, TREE_TIMEOUT)
            .unwrap_or_else(|error| panic!("cycle {cycle}: grandchild missing: {error}"));
        tree.job()
            .terminate(1)
            .unwrap_or_else(|error| panic!("cycle {cycle}: terminate failed: {error}"));
        let proof = tree
            .job()
            .wait_empty(EMPTY_TIMEOUT)
            .unwrap_or_else(|error| panic!("cycle {cycle}: job not empty: {error}"));
        assert!(
            proof.process_ids.is_empty() && proof.accounting.active_processes == 0,
            "cycle {cycle}: {:?}",
            proof
        );
    }
}

#[test]
fn spawn_failure_leaves_job_empty() {
    let job = Job::create().expect("create configured job");
    let error = job
        .spawn_suspended("vestry-t54-definitely-not-a-real-program.exe")
        .expect_err("missing executable must fail creation");
    assert_eq!(error.op(), "create_process_suspended");
    assert!(
        job.process_ids().expect("enumerate job").is_empty(),
        "failed creation must not leave a member behind"
    );
    drop(job);
}
