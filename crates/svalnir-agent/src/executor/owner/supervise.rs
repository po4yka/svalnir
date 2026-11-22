//! The supervision of one command: its process group, its deadline, the
//! stop conditions, and the bounded tail of its output.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::executor::fs::{Stop, StopSignal};

/// The bytes of the end of one output stream that the tail keeps. The two
/// streams together keep at most 4 KiB.
const TAIL_BYTES_PER_STREAM: usize = 2048;

/// The interval of the readings of the exit of the command.
const EXIT_POLL: Duration = Duration::from_millis(10);

/// The time that the readers of the output have after the end of the
/// group.
const READER_GRACE: Duration = Duration::from_millis(500);

/// The command of one step, as the sealed plan binds it.
#[derive(Debug, Clone)]
pub(super) struct CommandSpec {
    pub(super) executable: PathBuf,
    pub(super) arguments: Vec<String>,
    pub(super) environment: Vec<(String, String)>,
    pub(super) working_directory: PathBuf,
}

/// How the command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ending {
    /// The command exited. `children_remained` is true when a process of
    /// its group ran after the exit; the executor stopped the group.
    Exited {
        status: ExitStatus,
        children_remained: bool,
    },
    /// The command passed its deadline. The executor stopped the group.
    Deadline,
    /// A stop condition arrived while the command ran. The executor
    /// stopped the group.
    Stopped(Stop),
    /// The state of the command could not be read. The executor stopped
    /// the group.
    Lost,
}

/// The result of one supervised command.
#[derive(Debug, Clone)]
pub(super) struct Supervised {
    pub(super) ending: Ending,
    /// The raw end of the output, before the redaction.
    pub(super) tail: Vec<u8>,
}

/// The limits of the supervision.
#[derive(Debug, Clone, Copy)]
pub(super) struct Supervision {
    pub(super) deadline: Duration,
    pub(super) stop_poll: Duration,
    pub(super) stop_grace: Duration,
}

/// Sends `signal` to each process of the group `group`. Returns false when
/// the group has no process (`ESRCH`).
fn signal_group(group: libc::pid_t, signal: libc::c_int) -> bool {
    // SAFETY: `kill` takes no pointer. A negative identifier names the
    // process group that `process_group(0)` made for the command, whose
    // identifier is the process ID of the command. The system does not
    // give that identifier to a new process or group while the command is
    // not collected or a member of its group lives, so the signal reaches
    // only the processes of the command. Signal 0 only examines the group.
    let result: libc::c_int = unsafe { libc::kill(-group, signal) };
    result == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Whether the group `group` has a process.
fn group_has_process(group: libc::pid_t) -> bool {
    signal_group(group, 0)
}

/// Stops the group of `child`: `SIGTERM`, a wait of at most `grace` for
/// the command and its group, then `SIGKILL`, and the collection of the
/// command.
fn stop_group(child: &mut Child, group: libc::pid_t, grace: Duration) {
    signal_group(group, libc::SIGTERM);
    let until: Instant = Instant::now() + grace;
    let mut collected: bool = false;
    while Instant::now() < until {
        if !collected {
            collected = matches!(child.try_wait(), Ok(Some(_)));
        }
        if collected && !group_has_process(group) {
            return;
        }
        thread::sleep(EXIT_POLL);
    }
    signal_group(group, libc::SIGKILL);
    if !collected {
        drop(child.kill());
        drop(child.wait());
    }
}

/// Keeps the last `TAIL_BYTES_PER_STREAM` bytes of `reader` and discards
/// the rest, so that the command does not wait on a full pipe.
fn read_tail(mut reader: impl Read) -> Vec<u8> {
    let mut kept: VecDeque<u8> = VecDeque::with_capacity(TAIL_BYTES_PER_STREAM);
    let mut buffer: [u8; 8192] = [0; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                for byte in &buffer[..count] {
                    if kept.len() == TAIL_BYTES_PER_STREAM {
                        kept.pop_front();
                    }
                    kept.push_back(*byte);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    kept.into_iter().collect()
}

/// Starts a reader of one output stream on its own thread. `None` when no
/// thread starts: the stream is then closed, and the command gets an
/// error at its next write to it.
fn spawn_reader(reader: Option<impl Read + Send + 'static>) -> Option<mpsc::Receiver<Vec<u8>>> {
    let reader = reader?;
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("owner-operation-output".to_owned())
        .spawn(move || {
            drop(sender.send(read_tail(reader)));
        })
        .ok()?;
    Some(receiver)
}

/// Waits for the command until it exits, passes `limits.deadline`, or
/// `signal` gives a stop. Reads `signal` at intervals of at most
/// `limits.stop_poll`.
fn wait(
    child: &mut Child,
    group: libc::pid_t,
    limits: &Supervision,
    signal: &dyn StopSignal,
) -> Ending {
    let started: Instant = Instant::now();
    let deadline: Instant = started + limits.deadline;
    let mut next_signal: Instant = started;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let children_remained: bool = group_has_process(group);
                if children_remained {
                    signal_group(group, libc::SIGKILL);
                }
                return Ending::Exited {
                    status,
                    children_remained,
                };
            }
            Ok(None) => {}
            Err(_) => {
                stop_group(child, group, limits.stop_grace);
                return Ending::Lost;
            }
        }
        let now: Instant = Instant::now();
        if now >= deadline {
            stop_group(child, group, limits.stop_grace);
            return Ending::Deadline;
        }
        if now >= next_signal {
            if let Some(stop) = signal.check() {
                stop_group(child, group, limits.stop_grace);
                return Ending::Stopped(stop);
            }
            next_signal = now + limits.stop_poll;
        }
        thread::sleep(EXIT_POLL.min(deadline.saturating_duration_since(now)));
    }
}

/// Runs `spec` under `limits`.
///
/// The command starts by its absolute path, so no `PATH` lookup and no
/// shell runs. It has only the environment of `spec`, the working directory
/// of `spec`, an empty standard input, and a process group of its own.
///
/// # Errors
///
/// Returns the error of the system when the command does not start. No
/// process of the command runs then.
pub(super) fn run(
    spec: &CommandSpec,
    limits: &Supervision,
    signal: &dyn StopSignal,
) -> io::Result<Supervised> {
    let mut command: Command = Command::new(&spec.executable);
    command
        .args(&spec.arguments)
        .env_clear()
        .envs(spec.environment.iter().map(|(name, value)| (name, value)))
        .current_dir(&spec.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A process group of its own, so that a stop reaches each child
        // of the command too.
        .process_group(0);
    let mut child: Child = command.spawn()?;
    let Ok(group) = libc::pid_t::try_from(child.id()) else {
        drop(child.kill());
        drop(child.wait());
        return Ok(Supervised {
            ending: Ending::Lost,
            tail: Vec::new(),
        });
    };
    let stdout = spawn_reader(child.stdout.take());
    let stderr = spawn_reader(child.stderr.take());
    let ending: Ending = wait(&mut child, group, limits, signal);
    let mut tail: Vec<u8> = Vec::new();
    for receiver in [stdout, stderr].into_iter().flatten() {
        if let Ok(part) = receiver.recv_timeout(READER_GRACE) {
            if !tail.is_empty() && !part.is_empty() {
                tail.push(b'\n');
            }
            tail.extend_from_slice(&part);
        }
    }
    Ok(Supervised { ending, tail })
}

/// The exit status of `status`: the exit code, or `128` plus the number of
/// the signal that ended the process.
pub(super) fn status_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| {
        status
            .signal()
            .map_or(-1, |signal| 128_i32.saturating_add(signal))
    })
}

/// The tail of the output as text for the log: each byte that is not
/// UTF-8 is replaced, the home directory is `~`, and each control
/// character is a space.
pub(super) fn redacted(tail: &[u8], home: &str) -> String {
    let text: String = String::from_utf8_lossy(tail).into_owned();
    let text: String = if home.len() > 1 {
        text.replace(home, "~")
    } else {
        text
    };
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}
