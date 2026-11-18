//! The user interrupts a command whose output pipe is full.
//!
//! The test makes its own pipe, fills it, and runs `monitor` with the write
//! end as standard output. `monitor` only reads the host. A timeout ends the
//! child, so that a hang fails the test and cannot stop the suite.

#![cfg(target_os = "macos")]

use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Sets or clears `O_NONBLOCK` on `fd`.
fn set_nonblocking(fd: &OwnedFd, on: bool) -> io::Result<()> {
    let raw: libc::c_int = fd.as_raw_fd();
    // SAFETY: `raw` is an open descriptor that `fd` owns.
    let flags: libc::c_int = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let wanted: libc::c_int = if on {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: `raw` is an open descriptor that `fd` owns.
    if unsafe { libc::fcntl(raw, libc::F_SETFL, wanted) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Writes to `fd` until the pipe has no room (`EWOULDBLOCK`).
fn fill(fd: &OwnedFd) -> io::Result<()> {
    let chunk: [u8; 512] = [b'x'; 512];
    loop {
        // SAFETY: `chunk` is a valid buffer of the given length.
        let written: isize =
            unsafe { libc::write(fd.as_raw_fd(), chunk.as_ptr().cast(), chunk.len()) };
        if written < 0 {
            let error: io::Error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(())
            } else {
                Err(error)
            };
        }
    }
}

fn wait_for(child: &mut Child, limit: Duration) -> io::Result<Option<ExitStatus>> {
    let start: Instant = Instant::now();
    while start.elapsed() < limit {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(None)
}

#[test]
fn an_interrupt_ends_a_stream_whose_output_pipe_is_full() -> io::Result<()> {
    let (mut reader, writer) = io::pipe()?;
    let writer: OwnedFd = OwnedFd::from(writer);
    set_nonblocking(&writer, true)?;
    fill(&writer)?;
    // Leave room for a part of one event only.
    let mut part: [u8; 100] = [0; 100];
    reader.read_exact(&mut part)?;
    set_nonblocking(&writer, false)?;
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_svalnir"))
        .args(["--format", "ndjson", "monitor", "--interval", "1s"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::sleep(Duration::from_secs(2));
    let pid: libc::pid_t = libc::pid_t::try_from(child.id())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    // SAFETY: `pid` is the child that this test started and still owns.
    let sent: libc::c_int = unsafe { libc::kill(pid, libc::SIGINT) };
    assert_eq!(sent, 0, "the signal was not sent");
    let status: Option<ExitStatus> = wait_for(&mut child, Duration::from_secs(5))?;
    if status.is_none() {
        child.kill()?;
        child.wait()?;
    }
    assert_eq!(
        status.and_then(|status| status.code()),
        Some(130),
        "the interrupt must end the command with status 130 within 5 s"
    );
    Ok(())
}
