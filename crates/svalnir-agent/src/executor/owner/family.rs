//! The live processes of a recorded command, for the acknowledgment and
//! the reconciliation (`docs/ACTION_CONTRACTS.md` section 7, "Recovery").
//!
//! The journal has the command (its process ID, its start time, and its
//! process group) and each descendant that the worker found, by process ID
//! and start time. A process counts only by its identity: the same process
//! ID with the same start time. The members of the process group count
//! only while the group is the group of the record: when a process with
//! the process ID of the group runs with a different start time, the group
//! identity was given again after the command, and its members are not the
//! command.
//!
//! A truncated record (the worker could not keep or the journal could not
//! write each descendant) counts as a live process until the system started
//! again after the command. After the exit of the command, a descendant
//! that it did not record has the launch process as its parent and is its
//! own responsible process, so no reading of the host can find it; only a
//! new start of the system shows that it ended.

use std::thread;
use std::time::{Duration, Instant};

use svalnir_core::process::ProcessStartTime;

use super::native;
use crate::journal::OwnerProcess;

/// The interval of the readings while a stop waits.
const POLL: Duration = Duration::from_millis(10);

/// The time between `SIGTERM` and `SIGKILL` at a stop of a recorded
/// command.
pub const RECORDED_STOP_GRACE: Duration = Duration::from_secs(2);

/// The live processes of the recorded command `process`: the command, the
/// members of its process group while the group is the group of the
/// record, and each recorded descendant, each with its start time.
fn live(process: &OwnerProcess) -> Vec<(libc::pid_t, ProcessStartTime)> {
    let mut found: Vec<(libc::pid_t, ProcessStartTime)> = Vec::new();
    let mut add = |pid: libc::pid_t, started: ProcessStartTime| {
        if !found.contains(&(pid, started)) {
            found.push((pid, started));
        }
    };
    if native::lives(process.pid, process.started) {
        add(process.pid, process.started);
    }
    // The group is the group of the record when no other process has its
    // identity now.
    let group_is_recorded: bool = native::start_time(process.group)
        .is_none_or(|started| process.group == process.pid && started == process.started);
    if group_is_recorded {
        for member in native::group_members(process.group) {
            if let Some(started) = native::start_time(member)
                && started >= process.started
            {
                add(member, started);
            }
        }
    }
    for descendant in &process.descendants {
        if native::lives(descendant.pid, descendant.started) {
            add(descendant.pid, descendant.started);
        }
    }
    found
}

/// Whether a process of the recorded command `process` lives, or can
/// live: a truncated record counts as live until the system started again
/// after the command.
pub fn process_lives(process: &OwnerProcess) -> bool {
    !live(process).is_empty() || (process.truncated && !booted_after(process))
}

/// Whether the system started after the start of the command `process`.
/// False when the system does not give its start time.
fn booted_after(process: &OwnerProcess) -> bool {
    native::boot_time().is_some_and(|booted| booted > process.started)
}

/// Sends `signal` to each process of `targets` that still has its start
/// time.
fn signal_each(targets: &[(libc::pid_t, ProcessStartTime)], signal: libc::c_int) {
    for (pid, started) in targets {
        if native::lives(*pid, *started) {
            native::signal(*pid, signal);
        }
    }
}

/// Stops each live process of the recorded command `process`: `SIGKILL` at
/// once to a process that is still suspended (it ran no instruction of the
/// command), `SIGTERM` to each other one, a wait of at most `grace`, a new
/// reading, and `SIGKILL` to each process that is left. Returns whether a
/// process of the command lives after the stop, as [`process_lives`]
/// reads it: a truncated record keeps it true.
pub fn stop_recorded(process: &OwnerProcess, grace: Duration) -> bool {
    let targets = live(process);
    if targets.is_empty() {
        return process_lives(process);
    }
    let (suspended, running): (Vec<_>, Vec<_>) = targets
        .into_iter()
        .partition(|(pid, _)| native::is_stopped(*pid));
    signal_each(&suspended, libc::SIGKILL);
    signal_each(&running, libc::SIGTERM);
    let until: Instant = Instant::now() + grace;
    while Instant::now() < until {
        if live(process).is_empty() {
            return process_lives(process);
        }
        thread::sleep(POLL);
    }
    signal_each(&live(process), libc::SIGKILL);
    let until: Instant = Instant::now() + grace;
    while Instant::now() < until {
        if live(process).is_empty() {
            return process_lives(process);
        }
        thread::sleep(POLL);
    }
    true
}
