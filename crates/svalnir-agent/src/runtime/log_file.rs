//! The bound of the log file of the agent.
//!
//! The service manager sends the standard error stream of the agent to
//! [`agent_log_path`](super::launch_agent::agent_log_path) and does not
//! rotate the file. [`BoundedLog`] is the writer of the structured log: when
//! the file is larger than its limit, the next write cuts the file to zero
//! and starts it with one line that says so. The writer counts the bytes
//! that it writes; a write of a different source to the same stream, for
//! example a panic message, counts when the count of the writer next
//! passes the limit and the writer reads the size of the file again. The
//! file thus stays below the limit plus one record plus those other
//! writes.
//!
//! Only the log file of the agent has a bound: a standard error stream
//! that is a different file, for example one that a person gave with
//! `2>file` in a foreground run, is never cut. A stream that is not a
//! regular file, for example a terminal, has no bound.
//!
//! The file is cut and not rotated: the service manager holds the open
//! file, and the agent has no other name for it.
// TODO(npochaev): keep the earlier part of the log in a second file
// (`agent.log.1`) when the agent opens the log file itself, so that a cut
// does not remove the records just before it.

use std::fs::File;
use std::io::{self, Seek as _, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

/// The largest size of the log file before a cut: 8 MiB.
pub const AGENT_LOG_LIMIT_BYTES: u64 = 8 * 1024 * 1024;

/// The first line of a log file after a cut.
pub const CUT_NOTICE: &str = "svalnir-agent: the log file reached its size limit and was cut; the earlier records are not kept\n";

#[derive(Debug)]
struct State {
    file: File,
    /// The size of the file as this writer knows it.
    size: u64,
}

/// The writer of the log of the agent, with a size bound.
#[derive(Debug, Clone)]
pub struct BoundedLog {
    /// `None`: the stream is not a regular file, and writes go to the
    /// standard error stream with no bound.
    state: Option<Arc<Mutex<State>>>,
    limit: u64,
}

impl BoundedLog {
    /// The writer of the standard error stream of this process. The
    /// stream has a bound only when it is the file at `log`, the log file
    /// of the agent ([`agent_log_path`](super::launch_agent::agent_log_path)
    /// of the checked home directory). `None`: no bound.
    #[must_use]
    pub fn standard_error(log: Option<&Path>, limit: u64) -> Self {
        use std::os::fd::AsFd as _;

        let file: Option<File> = io::stderr()
            .as_fd()
            .try_clone_to_owned()
            .ok()
            .map(File::from);
        match (file, log) {
            (Some(file), Some(log)) => Self::of_file_at(file, log, limit),
            _ => Self { state: None, limit },
        }
    }

    /// The writer of `file`, with a bound only when `file` is the file at
    /// `log`: the same device and inode.
    #[must_use]
    pub fn of_file_at(file: File, log: &Path, limit: u64) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        let same: bool = match (file.metadata(), std::fs::metadata(log)) {
            (Ok(stream), Ok(at)) => stream.dev() == at.dev() && stream.ino() == at.ino(),
            _ => false,
        };
        if same {
            Self::of_file(file, limit)
        } else {
            Self { state: None, limit }
        }
    }

    /// The writer of `file`, which a caller opened for appends. A file
    /// that is not a regular file has no bound.
    #[must_use]
    pub fn of_file(file: File, limit: u64) -> Self {
        match file.metadata() {
            Ok(metadata) if metadata.is_file() => Self {
                state: Some(Arc::new(Mutex::new(State {
                    size: metadata.len(),
                    file,
                }))),
                limit,
            },
            _ => Self { state: None, limit },
        }
    }

    /// A writer for one record.
    #[must_use]
    pub fn writer(&self) -> BoundedLogWriter<'_> {
        BoundedLogWriter { log: self }
    }

    fn write_record(&self, buffer: &[u8]) -> io::Result<usize> {
        let Some(state) = &self.state else {
            return io::stderr().write(buffer);
        };
        // A panic in a different write leaves the state usable: the size
        // is only an estimate, and the next check reads the file again.
        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
        let length: u64 = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        if state.size.saturating_add(length) > self.limit {
            // A different writer of the same file, for example the
            // service manager, can have changed its size.
            state.size = state
                .file
                .metadata()
                .map_or(state.size, |metadata| metadata.len());
            // A cut that fails does not stop the log: the record is
            // written, and the next write that passes the limit tries the
            // cut again.
            if state.size.saturating_add(length) > self.limit && state.file.set_len(0).is_ok() {
                // The offset of a stream with no `O_APPEND` flag stays at
                // the old end after the cut; the next write would leave a
                // hole. A stream with the flag writes at the end in each
                // case.
                state.size = 0;
                if state.file.seek(SeekFrom::Start(0)).is_ok()
                    && state.file.write_all(CUT_NOTICE.as_bytes()).is_ok()
                {
                    state.size = u64::try_from(CUT_NOTICE.len()).unwrap_or(u64::MAX);
                }
            }
        }
        let written: usize = state.file.write(buffer)?;
        state.size = state
            .size
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        Ok(written)
    }
}

/// The writer of one record of a [`BoundedLog`].
#[derive(Debug)]
pub struct BoundedLogWriter<'a> {
    log: &'a BoundedLog,
}

impl Write for BoundedLogWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.log.write_record(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &self.log.state {
            Some(state) => state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .file
                .flush(),
            None => io::stderr().flush(),
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BoundedLog {
    type Writer = BoundedLogWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        self.writer()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    use super::{BoundedLog, CUT_NOTICE};

    fn append(path: &std::path::Path) -> std::fs::File {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap()
    }

    #[test]
    fn a_log_below_its_limit_keeps_each_record() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.log");
        let log = BoundedLog::of_file(append(&path), 1024);
        log.writer().write_all(b"first\n").unwrap();
        log.writer().write_all(b"second\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\nsecond\n");
    }

    #[test]
    fn a_log_over_its_limit_is_cut_and_says_so() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.log");
        // A file of an earlier start that is already over the limit.
        std::fs::write(&path, vec![b'x'; 300]).unwrap();
        let limit: u64 = 256;
        let log = BoundedLog::of_file(append(&path), limit);
        for index in 0..100 {
            log.writer()
                .write_all(format!("record {index:03}\n").as_bytes())
                .unwrap();
            let size: u64 = std::fs::metadata(&path).unwrap().len();
            assert!(size <= limit, "{size}");
        }
        let text: String = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(CUT_NOTICE), "{text}");
        assert!(text.ends_with("record 099\n"), "{text}");
        assert!(!text.contains('x'), "{text}");
    }

    #[test]
    fn a_cut_of_a_stream_with_no_append_flag_leaves_no_hole() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.log");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let log = BoundedLog::of_file(file, 200);
        for _ in 0..40 {
            log.writer().write_all(b"0123456789\n").unwrap();
        }
        let bytes: Vec<u8> = std::fs::read(&path).unwrap();
        assert!(!bytes.contains(&0), "{bytes:?}");
        assert!(bytes.starts_with(CUT_NOTICE.as_bytes()));
    }

    #[test]
    fn a_stream_that_is_not_the_log_file_of_the_agent_is_never_cut() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("agent.log");
        std::fs::write(&log, b"").unwrap();
        // A file that a person gave as the standard error stream.
        let other = directory.path().join("output.txt");
        std::fs::write(&other, vec![b'k'; 500]).unwrap();
        let writer = BoundedLog::of_file_at(append(&other), &log, 100);
        assert!(writer.state.is_none());
        // The writer has no cut for that file.
        assert_eq!(std::fs::metadata(&other).unwrap().len(), 500);
        // The log file of the agent has the bound.
        let bounded = BoundedLog::of_file_at(append(&log), &log, 100);
        assert!(bounded.state.is_some());
        // A log path that does not exist gives no bound.
        let absent = BoundedLog::of_file_at(append(&other), &directory.path().join("absent"), 1);
        assert!(absent.state.is_none());
    }

    #[test]
    fn a_stream_that_is_not_a_regular_file_has_no_bound() {
        let log = BoundedLog::of_file(std::fs::File::open("/dev/null").unwrap(), 1);
        assert!(log.state.is_none());
    }
}
