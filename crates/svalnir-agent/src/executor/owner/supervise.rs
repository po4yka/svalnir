//! The supervision of one command after its start: its process group, its
//! descendants, the processes for which it is responsible, its deadline,
//! the stop request, and the bounded tail of its output.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::c_int;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use svalnir_core::process::ProcessStartTime;

use super::native::{self, Responsibility, Wait};
use crate::executor::fs::Stop;
use crate::journal::{DescendantChange, ProcessRecord};

/// The bytes of the end of one output stream that the tail keeps.
const TAIL_BYTES_PER_STREAM: usize = 2048;

/// The interval of the readings of the exit of the command.
const EXIT_POLL: Duration = Duration::from_millis(10);

/// The time that the readers of the output have to read the end of their
/// streams after the end of the command.
pub(super) const READER_GRACE: Duration = Duration::from_millis(500);

/// The timeout of one `poll` call of a reader.
const READER_POLL_MS: c_int = 50;

/// How the command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ending {
    /// The command exited with this status word. `clean` is true when no
    /// process of the command is left, each output stream ended, and the
    /// set of descendants was never truncated.
    Exited { status: c_int, clean: bool },
    /// The command passed its deadline. Its processes were stopped.
    Deadline,
    /// A stop request arrived while the command ran. Its processes were
    /// stopped.
    Stopped(Stop),
    /// The state of the command could not be read. Its processes were
    /// stopped.
    Lost,
}

/// The result of one supervised command.
#[derive(Debug, Clone)]
pub(super) struct Supervised {
    pub(super) ending: Ending,
    /// True when a live descendant found no room in the set of the
    /// descendants: the worker cannot know each process of the command.
    pub(super) truncated: bool,
    /// The raw end of the standard output and of the standard error,
    /// before the redaction.
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

/// The limits of the supervision.
#[derive(Debug, Clone, Copy)]
pub(super) struct Supervision {
    pub(super) deadline: Duration,
    pub(super) stop_poll: Duration,
    pub(super) stop_grace: Duration,
    /// The largest number of live descendants that the set keeps. When a
    /// new descendant finds no room after the dead ones went, the set is
    /// truncated, and the command cannot end clean.
    pub(super) max_tracked: usize,
}

/// The stop request of the coordinator, which the worker reads.
pub(super) type StopCell = std::sync::Mutex<Option<Stop>>;

/// Reads the stop request. A poisoned cell is a stop.
pub(super) fn requested(cell: &StopCell) -> Option<Stop> {
    match cell.lock() {
        Ok(stop) => *stop,
        Err(_) => Some(Stop::Canceled),
    }
}

/// One reader of an output stream on its own thread.
struct Reader {
    done: mpsc::Receiver<(Vec<u8>, bool)>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// Keeps the last bytes of `fd` until its end or until `stop`. Returns the
/// tail and whether the end of the stream was read.
fn read_tail(fd: &OwnedFd, stop: &AtomicBool) -> (Vec<u8>, bool) {
    let mut kept: VecDeque<u8> = VecDeque::with_capacity(TAIL_BYTES_PER_STREAM);
    let mut buffer: [u8; 4096] = [0; 4096];
    let raw: c_int = fd.as_raw_fd();
    loop {
        if stop.load(Ordering::Acquire) {
            return (kept.into_iter().collect(), false);
        }
        let mut entry = libc::pollfd {
            fd: raw,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `entry` is one valid `pollfd` for the call.
        let ready: c_int = unsafe { libc::poll(&raw mut entry, 1, READER_POLL_MS) };
        if ready == 0 {
            continue;
        }
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return (kept.into_iter().collect(), false);
        }
        // SAFETY: `buffer` has room for its length, and `raw` is an open
        // descriptor of `fd`.
        let count: isize = unsafe { libc::read(raw, buffer.as_mut_ptr().cast(), buffer.len()) };
        match usize::try_from(count) {
            Ok(0) => return (kept.into_iter().collect(), true),
            Ok(count) => {
                for byte in &buffer[..count] {
                    if kept.len() == TAIL_BYTES_PER_STREAM {
                        kept.pop_front();
                    }
                    kept.push_back(*byte);
                }
            }
            Err(_) => {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return (kept.into_iter().collect(), false);
            }
        }
    }
}

impl Reader {
    fn start(fd: OwnedFd) -> Self {
        let (sender, done) = mpsc::channel();
        let stop: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let flag: Arc<AtomicBool> = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("owner-operation-output".to_owned())
            .spawn(move || {
                drop(sender.send(read_tail(&fd, &flag)));
            })
            .ok();
        Self { done, stop, thread }
    }

    /// Waits until `until` for the end of the stream, then stops and joins
    /// the thread. Returns the tail and whether the end was read.
    fn finish(mut self, until: Instant) -> (Vec<u8>, bool) {
        let wait: Duration = until.saturating_duration_since(Instant::now());
        let result = self.done.recv_timeout(wait).ok();
        self.stop.store(true, Ordering::Release);
        let result = result.or_else(|| self.done.recv_timeout(READER_GRACE).ok());
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
        result.unwrap_or_default()
    }
}

/// The processes of one command: the leader, its process group, the
/// descendants that the worker saw, and the processes for which the
/// leader is responsible.
struct Family {
    leader: libc::pid_t,
    leader_started: ProcessStartTime,
    responsibility: Responsibility,
    owner: u32,
    /// The descendants that the worker saw, at most `limit`. A dead one
    /// goes when a new one needs its room.
    tracked: BTreeMap<libc::pid_t, ProcessStartTime>,
    limit: usize,
    /// True after a live descendant found no room in the set.
    truncated: bool,
    /// The process IDs of the last listing of the host, so that a
    /// responsibility reading examines only the processes that are new.
    listed: BTreeSet<libc::pid_t>,
    /// The descendants that the worker found and did not report yet.
    unreported: Vec<ProcessRecord>,
    /// The reported descendants that went from the set and that the
    /// worker did not report as gone yet.
    gone: Vec<ProcessRecord>,
    /// True after the worker reported the truncation.
    truncation_reported: bool,
}

impl Family {
    /// Adds `pid` to the set when it is new. When the set is full, the
    /// dead descendants go first; when it is full of live ones, the set is
    /// truncated.
    fn add(&mut self, pid: libc::pid_t, started: ProcessStartTime) -> bool {
        match self.tracked.get(&pid) {
            Some(known) if *known == started => return false,
            // The process ID was given again: the earlier process ended.
            Some(known) => {
                let earlier = ProcessRecord {
                    pid,
                    started: *known,
                };
                self.forget(earlier);
            }
            None => {}
        }
        if self.tracked.len() >= self.limit {
            self.prune();
        }
        if self.tracked.len() >= self.limit {
            self.truncated = true;
            return false;
        }
        self.tracked.insert(pid, started);
        self.unreported.push(ProcessRecord { pid, started });
        true
    }

    /// Removes `record` from the set, and from the journal by the next
    /// report when the worker reported it before.
    fn forget(&mut self, record: ProcessRecord) {
        self.tracked.remove(&record.pid);
        if let Some(index) = self.unreported.iter().position(|found| *found == record) {
            self.unreported.swap_remove(index);
        } else {
            self.gone.push(record);
        }
    }

    /// Removes each dead descendant from the set.
    fn prune(&mut self) {
        let dead: Vec<ProcessRecord> = self
            .tracked
            .iter()
            .filter(|(pid, started)| !native::lives(**pid, **started))
            .map(|(pid, started)| ProcessRecord {
                pid: *pid,
                started: *started,
            })
            .collect();
        for record in dead {
            self.forget(record);
        }
    }

    /// The change of the set since the last report, or `None` when it has
    /// none.
    fn change(&mut self) -> Option<DescendantChange> {
        let truncated: bool = self.truncated && !self.truncation_reported;
        if self.unreported.is_empty() && self.gone.is_empty() && !truncated {
            return None;
        }
        self.truncation_reported = self.truncated;
        Some(DescendantChange {
            found: std::mem::take(&mut self.unreported),
            gone: std::mem::take(&mut self.gone),
            truncated: self.truncated,
        })
    }

    /// Adds the live descendants of the leader and of each tracked process.
    /// Returns whether a descendant was new.
    fn track(&mut self) -> bool {
        let mut grew: bool = false;
        let mut queue: Vec<libc::pid_t> = vec![self.leader];
        queue.extend(self.tracked.keys().copied());
        while let Some(parent) = queue.pop() {
            for child in native::children(parent) {
                if let Some(started) = native::start_time(child)
                    && self.add(child, started)
                {
                    grew = true;
                    queue.push(child);
                }
            }
        }
        grew
    }

    /// Adds the processes for which the leader is responsible now. The
    /// system gives that responsibility only while the leader lives: after
    /// its exit, a process that it left is its own responsible process. So
    /// the worker reads it while the command runs. The responsibility of a
    /// process is set at its start, so each reading examines only the
    /// processes that the last listing of the host did not have. Returns
    /// whether a process was new.
    fn track_responsible(&mut self) -> bool {
        let listed: BTreeSet<libc::pid_t> = native::all_processes().into_iter().collect();
        let new: Vec<libc::pid_t> = listed.difference(&self.listed).copied().collect();
        self.listed = listed;
        let mut grew: bool = false;
        for (pid, started) in self.responsible(new) {
            grew |= self.add(pid, started);
        }
        grew
    }

    /// The processes of `candidates` of the user, other than this process
    /// and the leader, whose responsible process is the leader and that
    /// started after it.
    fn responsible(
        &self,
        candidates: impl IntoIterator<Item = libc::pid_t>,
    ) -> Vec<(libc::pid_t, ProcessStartTime)> {
        // SAFETY: `getpid` has no argument and cannot fail.
        let own: libc::pid_t = unsafe { libc::getpid() };
        candidates
            .into_iter()
            .filter(|pid| *pid != own && *pid != self.leader)
            .filter(|pid| self.responsibility.responsible_for(*pid) == Some(self.leader))
            .filter(|pid| native::owner_of(*pid) == Some(self.owner))
            .filter_map(|pid| native::start_time(pid).map(|started| (pid, started)))
            .filter(|(_, started)| *started >= self.leader_started)
            .collect()
    }

    /// The live processes of the user for which the leader is responsible:
    /// a full reading of the host.
    fn responsible_survivors(&self) -> Vec<(libc::pid_t, ProcessStartTime)> {
        self.responsible(native::all_processes())
    }

    /// The live tracked descendants and the responsible survivors.
    fn survivors(&self) -> Vec<(libc::pid_t, ProcessStartTime)> {
        let mut survivors: Vec<(libc::pid_t, ProcessStartTime)> = self
            .tracked
            .iter()
            .filter(|(pid, started)| native::lives(**pid, **started))
            .map(|(pid, started)| (*pid, *started))
            .collect();
        for found in self.responsible_survivors() {
            if !survivors.contains(&found) {
                survivors.push(found);
            }
        }
        survivors
    }

    fn group_has_process(&self) -> bool {
        native::signal(-self.leader, 0)
    }

    /// Sends `signal` to the group and to each survivor that still has the
    /// start time of its record.
    fn signal_each(&self, signal: c_int, survivors: &[(libc::pid_t, ProcessStartTime)]) {
        native::signal(-self.leader, signal);
        for (pid, started) in survivors {
            if native::lives(*pid, *started) {
                native::signal(*pid, signal);
            }
        }
    }

    /// Stops each process of the command: `SIGTERM`, a wait of at most
    /// `grace`, a new reading, then `SIGKILL` to each process that is left.
    /// Collects the leader when it ran.
    fn stop(&mut self, grace: Duration, mut collected: bool) {
        self.track();
        let survivors = self.survivors();
        self.signal_each(libc::SIGTERM, &survivors);
        let until: Instant = Instant::now() + grace;
        while Instant::now() < until {
            if !collected {
                collected = !matches!(native::try_wait(self.leader), Wait::Running);
            }
            if collected && !self.group_has_process() && self.survivors().is_empty() {
                return;
            }
            thread::sleep(EXIT_POLL);
        }
        // The group and each survivor are read again before the second
        // signal.
        let survivors = self.survivors();
        if self.group_has_process() || !survivors.is_empty() {
            self.signal_each(libc::SIGKILL, &survivors);
        }
        if !collected {
            native::signal(self.leader, libc::SIGKILL);
            while matches!(native::try_wait(self.leader), Wait::Running) {
                thread::sleep(EXIT_POLL);
            }
        }
    }
}

/// The command after its suspended start.
pub(super) struct Command {
    pub(super) pid: libc::pid_t,
    pub(super) started: ProcessStartTime,
    pub(super) stdout: OwnedFd,
    pub(super) stderr: OwnedFd,
}

/// Stops a command that never ran: `SIGKILL` to the suspended process and
/// its collection.
pub(super) fn kill_suspended(pid: libc::pid_t) {
    native::signal(-pid, libc::SIGKILL);
    native::signal(pid, libc::SIGKILL);
    while matches!(native::try_wait(pid), Wait::Running) {
        thread::sleep(EXIT_POLL);
    }
}

/// Resumes the suspended `command` and supervises it under `limits` until
/// it ends, passes its deadline, or `stop` has a request.
pub(super) fn run(
    command: Command,
    responsibility: Responsibility,
    limits: &Supervision,
    stop: &StopCell,
    report: &dyn Fn(&DescendantChange),
) -> Supervised {
    let Command {
        pid,
        started,
        stdout,
        stderr,
    } = command;
    let stdout: Reader = Reader::start(stdout);
    let stderr: Reader = Reader::start(stderr);
    let mut family = Family {
        leader: pid,
        leader_started: started,
        responsibility,
        owner: native::owner_of(pid).unwrap_or(u32::MAX),
        tracked: BTreeMap::new(),
        limit: limits.max_tracked,
        truncated: false,
        listed: BTreeSet::new(),
        unreported: Vec::new(),
        gone: Vec::new(),
        truncation_reported: false,
    };
    native::signal(pid, libc::SIGCONT);
    let begun: Instant = Instant::now();
    let deadline: Instant = begun + limits.deadline;
    let mut next_stop: Instant = begun;
    let ending: Ending = loop {
        match native::try_wait(pid) {
            Wait::Ended(status) => {
                family.track();
                if let Some(change) = family.change() {
                    report(&change);
                }
                let readers_until: Instant = Instant::now() + READER_GRACE;
                let (out, out_end) = stdout.finish(readers_until);
                let (err, err_end) = stderr.finish(readers_until);
                let left: bool = family.group_has_process() || !family.survivors().is_empty();
                if left {
                    family.stop(limits.stop_grace, true);
                }
                return Supervised {
                    ending: Ending::Exited {
                        status,
                        clean: !left && out_end && err_end && !family.truncated,
                    },
                    truncated: family.truncated,
                    stdout: out,
                    stderr: err,
                };
            }
            Wait::Failed => {
                family.stop(limits.stop_grace, false);
                break Ending::Lost;
            }
            Wait::Running => {}
        }
        family.track();
        family.track_responsible();
        if let Some(change) = family.change() {
            report(&change);
        }
        let now: Instant = Instant::now();
        if now >= deadline {
            family.stop(limits.stop_grace, false);
            break Ending::Deadline;
        }
        if now >= next_stop {
            if let Some(halt) = requested(stop) {
                family.stop(limits.stop_grace, false);
                break Ending::Stopped(halt);
            }
            next_stop = now + limits.stop_poll;
        }
        thread::sleep(EXIT_POLL.min(deadline.saturating_duration_since(now)));
    };
    let until: Instant = Instant::now() + READER_GRACE;
    let (out, _) = stdout.finish(until);
    let (err, _) = stderr.finish(until);
    Supervised {
        ending,
        truncated: family.truncated,
        stdout: out,
        stderr: err,
    }
}

/// The exit status of a status word: the exit code, or `128` plus the
/// number of the signal that ended the process.
pub(super) fn status_code(status: c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128_i32.saturating_add(libc::WTERMSIG(status))
    } else {
        -1
    }
}

/// Whether a status word is a normal exit with status 0.
pub(super) fn is_success(status: c_int) -> bool {
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// Replaces the value that follows each `marker` up to the next white
/// space, quote, or `&`.
fn mask_after(text: &str, marker: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut rest: &str = text;
    while let Some(index) = rest.find(marker) {
        let (before, after) = rest.split_at(index + marker.len());
        out.push_str(before);
        let end: usize = after
            .find(|character: char| {
                character.is_whitespace() || matches!(character, '"' | '\'' | '&')
            })
            .unwrap_or(after.len());
        if end > 0 {
            out.push_str("***");
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// Replaces the user information of each URL: `scheme://user:secret@`
/// becomes `scheme://***@`.
fn mask_userinfo(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut rest: &str = text;
    while let Some(index) = rest.find("://") {
        let (before, after) = rest.split_at(index + 3);
        out.push_str(before);
        let authority_end: usize = after
            .find(|character: char| {
                character.is_whitespace() || matches!(character, '/' | '"' | '\'')
            })
            .unwrap_or(after.len());
        match after[..authority_end].rfind('@') {
            Some(at) => {
                out.push_str("***");
                rest = &after[at..];
            }
            None => rest = after,
        }
    }
    out.push_str(rest);
    out
}

/// The longest text of one stream in the tail.
const MAX_TAIL_TEXT: usize = TAIL_BYTES_PER_STREAM;

/// The tail of one output stream as text for the log: each byte that is
/// not UTF-8 is replaced, the home directory is `~`, URL user information
/// and token values are replaced, each control character other than a line
/// end is a space, and the text is cut at a line boundary, which is also a
/// UTF-8 boundary. The lines of the result are joined with ` | `.
pub(super) fn redacted(tail: &[u8], home: &str) -> String {
    let text: String = String::from_utf8_lossy(tail).into_owned();
    let text: String = if home.len() > 1 {
        text.replace(home, "~")
    } else {
        text
    };
    let text: String = mask_userinfo(&text);
    let text: String = mask_after(&text, "_authToken=");
    let text: String = mask_after(&text, "token=");
    let text: String = mask_after(&text, "Bearer ");
    let text: String = text
        .chars()
        .map(|character| {
            if character.is_control() && character != '\n' {
                ' '
            } else {
                character
            }
        })
        .collect();
    // The first line can be the second part of a line that the bound cut,
    // so it goes when a later line exists.
    let mut lines: Vec<&str> = text
        .split('\n')
        .filter(|line| !line.trim().is_empty())
        .collect();
    if tail.len() >= TAIL_BYTES_PER_STREAM && lines.len() > 1 {
        lines.remove(0);
    }
    let mut joined: String = String::new();
    for line in lines.iter().rev() {
        if joined.len() + line.len() + 3 > MAX_TAIL_TEXT {
            break;
        }
        joined = if joined.is_empty() {
            (*line).to_owned()
        } else {
            format!("{line} | {joined}")
        };
    }
    joined
}
