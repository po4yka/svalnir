//! `monitor`: a stream of host snapshots at a fixed interval.
//!
//! The stream has no background agent behind it: each event is a new reading
//! of the host by this process. The first event is a `snapshot`; each later
//! event is an `observation_update` with the same data and the swap rates
//! since the event before it. The stream ends on Ctrl+C with exit status 130
//! and on a closed pipe quietly. Ending the stream changes nothing else.

use std::io::{self, Write};
use std::time::Duration;

use serde::Serialize;
use svalnir_agent::platform::memory::VmStatistics;
use svalnir_core::time::WallTime;

use super::resources::{self, DiskView, HostReading, MemoryView, SwapView};
use super::{CommandFailure, Invocation, json_line, write_interruptible};
use crate::cli::{Format, MonitorArgs};
use crate::host::{Host, ScopeCoverage};
use crate::interrupt::Interrupt;
use crate::output::{ErrorBody, ExitStatus, SCHEMA_VERSION};

/// The longest sleep between two checks of the interrupt flag.
const INTERRUPT_POLL: Duration = Duration::from_millis(100);

/// The data of one event.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SampleView {
    captured_at: WallTime,
    disk: DiskView,
    memory: MemoryView,
    swap: SwapView,
    coverage: ScopeCoverage,
}

impl SampleView {
    pub(crate) fn new(reading: &HostReading, earlier: Option<&VmStatistics>) -> Self {
        let mut coverage = ScopeCoverage::new();
        Self {
            captured_at: reading.memory.pressure.sample.captured_at,
            disk: DiskView::new(&reading.disk, &mut coverage),
            memory: MemoryView::new(&reading.memory, &mut coverage),
            swap: SwapView::new(&reading.memory, earlier, &mut coverage),
            coverage,
        }
    }

    /// One line of the text form.
    pub(crate) fn line(&self, reading: &HostReading) -> String {
        let available: String = match &reading.disk {
            resources::DiskReading::Measured { capacity, .. } => {
                crate::text::observed_bytes(&capacity.available)
            }
            resources::DiskReading::CapacityUnavailable { .. } => {
                "unavailable (capacity not collected)".to_owned()
            }
            resources::DiskReading::Unresolved(_) => "unavailable (volume not resolved)".to_owned(),
        };
        format!(
            "{}  pressure {}  disk available {}  swap used {}  swap-in {}  swap-out {}\n",
            self.captured_at,
            self.memory.pressure_text(),
            available,
            self.swap.used_text(),
            self.swap.activity().swapins.text(),
            self.swap.activity().swapouts.text(),
        )
    }
}

/// One line of the NDJSON stream (`docs/INTERFACES.md` section 11).
#[derive(Debug, Serialize)]
struct StreamLine<'a, T> {
    schema_version: u32,
    stream_id: &'a str,
    stream_epoch: &'a str,
    /// The position of the event in the stream, from 0, as a base-10 string.
    sequence: String,
    event_type: &'static str,
    data: &'a T,
}

/// The source of the readings and of the waits of a stream.
pub(crate) trait Sampler {
    /// Reads the host one time.
    fn sample(&mut self) -> Result<HostReading, ErrorBody>;

    /// Waits for `interval`, or less when the user interrupts.
    fn wait(&mut self, interval: Duration, interrupt: &Interrupt);
}

struct HostSampler {
    host: Host,
}

impl Sampler for HostSampler {
    fn sample(&mut self) -> Result<HostReading, ErrorBody> {
        resources::collect(&self.host)
    }

    fn wait(&mut self, interval: Duration, interrupt: &Interrupt) {
        let mut remaining: Duration = interval;
        while !remaining.is_zero() && !interrupt.is_requested() {
            let step: Duration = remaining.min(INTERRUPT_POLL);
            std::thread::sleep(step);
            remaining = remaining.saturating_sub(step);
        }
    }
}

/// Flushes `stdout`. A flush that `EINTR` ended is tried again until the
/// user interrupts.
fn flush_interruptible(stdout: &mut dyn Write, interrupt: &Interrupt) -> io::Result<()> {
    loop {
        match stdout.flush() {
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted && !interrupt.is_requested() => {}
            other => return other,
        }
    }
}

/// Writes events until the user interrupts or `max_events` is reached.
///
/// `max_events` is `None` for the command. A test gives a number.
///
/// An output error that occurs after the user interrupted (a closed pipe,
/// because the reader got the same signal, or `EINTR`) ends the stream with
/// status 130, not with the quiet success of a closed pipe.
pub(crate) fn stream(
    sampler: &mut dyn Sampler,
    interval: Duration,
    stream_epoch: &str,
    max_events: Option<u64>,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let interrupt: Interrupt = invocation.environment.interrupt.clone();
    match stream_events(sampler, interval, stream_epoch, max_events, invocation) {
        Err(CommandFailure::Output(error))
            if interrupt.is_requested()
                && matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::Interrupted
                ) =>
        {
            Ok(ExitStatus::Interrupted)
        }
        other => other,
    }
}

fn stream_events(
    sampler: &mut dyn Sampler,
    interval: Duration,
    stream_epoch: &str,
    max_events: Option<u64>,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let interrupt: Interrupt = invocation.environment.interrupt.clone();
    interrupt.arm();
    let stream_id: String = invocation.request_id.as_str().to_owned();
    // A stream has no envelope, so each advisory finding goes to stderr.
    for warning in std::mem::take(&mut invocation.warnings) {
        writeln!(invocation.stderr, "warning: {}", warning.message)?;
    }
    if invocation.format == Format::Text {
        write_interruptible(
            invocation.stdout,
            b"This stream reads the host in this process. No background agent and no policy is active.\n",
            &interrupt,
        )?;
    }
    let mut earlier: Option<VmStatistics> = None;
    let mut sequence: u64 = 0;
    loop {
        if interrupt.is_requested() {
            return Ok(ExitStatus::Interrupted);
        }
        let reading: HostReading = match sampler.sample() {
            Ok(reading) => reading,
            // Each line of the stream has one shape. A collection failure
            // is the last event of the stream, not a response envelope.
            Err(error) if invocation.format != Format::Text => {
                let status: ExitStatus = error.exit_status();
                let line: Vec<u8> = json_line(&StreamLine {
                    schema_version: SCHEMA_VERSION,
                    stream_id: &stream_id,
                    stream_epoch,
                    sequence: sequence.to_string(),
                    event_type: "stream_error",
                    data: &error,
                })?;
                write_interruptible(invocation.stdout, &line, &interrupt)?;
                return Ok(status);
            }
            Err(error) => return Err(error.into()),
        };
        let view = SampleView::new(&reading, earlier.as_ref());
        let event: Vec<u8> = match invocation.format {
            Format::Text => view.line(&reading).into_bytes(),
            Format::Json | Format::Ndjson => json_line(&StreamLine {
                schema_version: SCHEMA_VERSION,
                stream_id: &stream_id,
                stream_epoch,
                sequence: sequence.to_string(),
                event_type: if sequence == 0 {
                    "snapshot"
                } else {
                    "observation_update"
                },
                data: &view,
            })?,
        };
        write_interruptible(invocation.stdout, &event, &interrupt)?;
        // A reader of a pipe gets each event when it is made.
        flush_interruptible(invocation.stdout, &interrupt)?;
        earlier = Some(reading.memory.vm);
        sequence = sequence.saturating_add(1);
        if max_events.is_some_and(|limit| sequence >= limit) {
            return Ok(ExitStatus::Success);
        }
        sampler.wait(interval, &interrupt);
    }
}

pub(crate) fn run(
    arguments: &MonitorArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let host: Host = Host::open()?;
    let stream_epoch: String = host
        .context()
        .identity()
        .collector_epoch
        .as_str()
        .to_owned();
    let mut sampler = HostSampler { host };
    stream(
        &mut sampler,
        arguments.interval,
        &stream_epoch,
        None,
        invocation,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use serde_json::Value;

    use super::{Sampler, stream};
    use crate::cli::Format;
    use crate::commands::resources::{DiskReading, HostReading};
    use crate::commands::{CommandFailure, Invocation};
    use crate::interrupt::Interrupt;
    use crate::output::{ErrorBody, ExitStatus};
    use crate::test_support::{environment, memory_snapshot_at, request_id, volume_capacity};

    /// Gives a new reading on each call and interrupts after `stop_after`
    /// waits.
    struct FakeSampler {
        fail_at: Option<u64>,
        samples: u64,
        waits: u64,
        stop_after: Option<u64>,
        flag: Arc<AtomicBool>,
    }

    impl Sampler for FakeSampler {
        fn sample(&mut self) -> Result<HostReading, ErrorBody> {
            if self.fail_at == Some(self.samples) {
                return Err(crate::host::collector_unavailable("synthetic failure"));
            }
            let (identity, capacity, foundation) = volume_capacity();
            let reading = HostReading {
                disk: DiskReading::Measured {
                    identity,
                    capacity,
                    foundation,
                },
                // Each sample is one second later and has 50 more swap-ins.
                memory: memory_snapshot_at(self.samples),
            };
            self.samples += 1;
            Ok(reading)
        }

        fn wait(&mut self, _interval: Duration, _interrupt: &Interrupt) {
            self.waits += 1;
            if self.stop_after.is_some_and(|limit| self.waits >= limit) {
                self.flag.store(true, Ordering::SeqCst);
            }
        }
    }

    fn run(
        format: Format,
        stop_after: Option<u64>,
        max_events: Option<u64>,
    ) -> (Result<ExitStatus, CommandFailure>, String) {
        let (mut environment, _directory) = environment();
        let (interrupt, flag) = Interrupt::manual();
        environment.interrupt = interrupt;
        let mut sampler = FakeSampler {
            fail_at: (max_events == Some(99)).then_some(1),
            samples: 0,
            waits: 0,
            stop_after,
            flag,
        };
        let request_id = request_id();
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        let result = {
            let mut invocation = Invocation {
                format,
                request_id: &request_id,
                environment: &environment,
                stdout: &mut stdout,
                stderr: &mut stderr,
                timeout: None,
                warnings: Vec::new(),
            };
            stream(
                &mut sampler,
                Duration::from_secs(1),
                "epoch_test",
                max_events,
                &mut invocation,
            )
        };
        (result, String::from_utf8(stdout).unwrap())
    }

    #[test]
    fn ndjson_has_one_event_on_each_line_with_an_exact_sequence() {
        let (result, stdout) = run(Format::Ndjson, None, Some(3));
        assert_eq!(result.unwrap(), ExitStatus::Success);
        let events: Vec<Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["event_type"], "snapshot");
        assert_eq!(events[1]["event_type"], "observation_update");
        assert_eq!(events[2]["sequence"], "2");
        assert_eq!(events[0]["stream_id"], "request_test");
        assert_eq!(events[0]["stream_epoch"], "epoch_test");
        assert_eq!(events[0]["schema_version"], 1);
        // The first event has one sample, so it has no rate.
        let first_rate = &events[0]["data"]["swap"]["activity"]["swapins"];
        assert_eq!(first_rate["availability"], "unavailable");
        assert_eq!(first_rate["reason"], "not_initialized");
        // 50 pages in one second.
        let rate = &events[1]["data"]["swap"]["activity"]["swapins"];
        assert_eq!(rate["availability"], "available");
        assert_eq!(rate["increase_pages"], "50");
        assert_eq!(rate["interval_ns"], "1000000000");
        assert!((rate["pages_per_second"].as_f64().unwrap() - 50.0).abs() < 1e-9);
        assert_eq!(events[1]["data"]["memory"]["pressure"]["value"], "normal");
    }

    #[test]
    fn an_interrupt_ends_the_stream_with_status_130() {
        let (result, stdout) = run(Format::Ndjson, Some(2), None);
        assert_eq!(result.unwrap(), ExitStatus::Interrupted);
        assert_eq!(stdout.lines().count(), 2);
        assert_eq!(ExitStatus::Interrupted.code(), 130);
    }

    /// A writer that sets the interrupt flag and then fails.
    struct FailingWriter {
        kind: std::io::ErrorKind,
        flag: Option<Arc<AtomicBool>>,
    }

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            if let Some(flag) = &self.flag {
                flag.store(true, Ordering::SeqCst);
            }
            Err(self.kind.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn run_with_writer(
        kind: std::io::ErrorKind,
        interrupted: bool,
    ) -> Result<ExitStatus, CommandFailure> {
        let (mut environment, _directory) = environment();
        let (interrupt, flag) = Interrupt::manual();
        environment.interrupt = interrupt;
        let mut sampler = FakeSampler {
            fail_at: None,
            samples: 0,
            waits: 0,
            stop_after: None,
            flag: Arc::clone(&flag),
        };
        let request_id = request_id();
        let mut stdout = FailingWriter {
            kind,
            flag: interrupted.then_some(flag),
        };
        let mut stderr: Vec<u8> = Vec::new();
        let mut invocation = Invocation {
            format: Format::Ndjson,
            request_id: &request_id,
            environment: &environment,
            stdout: &mut stdout,
            stderr: &mut stderr,
            timeout: None,
            warnings: Vec::new(),
        };
        stream(
            &mut sampler,
            Duration::from_secs(1),
            "epoch_test",
            None,
            &mut invocation,
        )
    }

    #[test]
    fn a_closed_pipe_after_an_interrupt_ends_with_status_130() {
        let result = run_with_writer(std::io::ErrorKind::BrokenPipe, true);
        assert_eq!(result.unwrap(), ExitStatus::Interrupted);
    }

    #[test]
    fn a_write_that_the_signal_ended_returns_status_130() {
        let result = run_with_writer(std::io::ErrorKind::Interrupted, true);
        assert_eq!(result.unwrap(), ExitStatus::Interrupted);
    }

    #[test]
    fn a_closed_pipe_without_an_interrupt_stays_an_output_error() {
        let result = run_with_writer(std::io::ErrorKind::BrokenPipe, false);
        assert!(matches!(
            result,
            Err(CommandFailure::Output(error)) if error.kind() == std::io::ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn a_collection_failure_is_the_last_event_of_the_stream() {
        // The fake sampler fails at its second sample for this event limit.
        let (result, stdout) = run(Format::Ndjson, None, Some(99));
        assert_eq!(result.unwrap(), ExitStatus::Unavailable);
        let events: Vec<Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1]["event_type"], "stream_error");
        assert_eq!(events[1]["sequence"], "1");
        assert_eq!(events[1]["stream_id"], "request_test");
        assert_eq!(events[1]["data"]["code"], "collector_unavailable");
    }

    #[test]
    fn the_text_form_has_one_line_for_each_sample() {
        let (result, stdout) = run(Format::Text, None, Some(2));
        assert_eq!(result.unwrap(), ExitStatus::Success);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("No background agent and no policy is active."));
        assert!(lines[1].contains("pressure normal"), "{}", lines[1]);
        assert!(lines[1].contains("swap-in unavailable (not_initialized)"));
        assert!(lines[2].contains("swap-in 50.0 pages/s"), "{}", lines[2]);
        assert!(lines[2].contains("disk available 100.0 GiB"));
    }
}
