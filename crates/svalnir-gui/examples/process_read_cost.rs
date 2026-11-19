//! Measures the cost of one process table read of the window: the call
//! that the Memory and Applications screens make at each poll
//! (`DataSource::processes` of the live source). Owner decision 15 of
//! 2026-11-19 keeps the intervals (2 s with the window in front, 30 s when
//! it is not active) and asks for this cost.
//!
//! The read is read-only: it reads the process inventory of this user and
//! signals nothing. The live source gets no state directory, so no journal
//! is opened.
//!
//! Usage: `cargo run -p svalnir-gui --example process_read_cost --release
//! -- [SAMPLES]` (at least 30; default 40). The example waits 500 ms between
//! two reads, so that one read does not start in the caches of the last.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a measurement tool prints its result"
)]

use std::{
    process::ExitCode,
    time::{Duration, Instant},
};
use svalnir_gui::data::{DataSource as _, live::LiveSource};

/// The least number of samples.
const MIN_SAMPLES: usize = 30;

/// The CPU time of this process, from `CLOCK_PROCESS_CPUTIME_ID`. `None`
/// when the clock gives no value.
fn process_cpu_time() -> Option<Duration> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a valid, writable `timespec` that lives for the
    // call; the call writes only to it.
    let status: libc::c_int =
        unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &raw mut time) };
    if status != 0 {
        return None;
    }
    Some(Duration::new(
        u64::try_from(time.tv_sec).ok()?,
        u32::try_from(time.tv_nsec).ok()?,
    ))
}

/// The value at the fraction `quantile` of the sorted `values`.
fn at(values: &[Duration], quantile: f64) -> Duration {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "an index of a short list"
    )]
    let index: usize = ((values.len().saturating_sub(1)) as f64 * quantile).round() as usize;
    values.get(index).copied().unwrap_or_default()
}

fn milliseconds(value: Duration) -> f64 {
    value.as_secs_f64() * 1_000.0
}

fn summary(name: &str, values: &mut [Duration]) -> Duration {
    values.sort();
    let total: Duration = values.iter().sum();
    let count: u32 = u32::try_from(values.len()).unwrap_or(u32::MAX).max(1);
    let median: Duration = at(values, 0.5);
    println!(
        "{name}: min {:.2} ms, median {:.2} ms, p90 {:.2} ms, max {:.2} ms, mean {:.2} ms",
        milliseconds(at(values, 0.0)),
        milliseconds(median),
        milliseconds(at(values, 0.9)),
        milliseconds(at(values, 1.0)),
        milliseconds(total / count),
    );
    median
}

fn main() -> ExitCode {
    let samples: usize = match std::env::args().nth(1).map(|text| text.parse::<usize>()) {
        None => 40,
        Some(Ok(count)) if count >= MIN_SAMPLES => count,
        Some(_) => {
            eprintln!("process_read_cost: SAMPLES must be a number of at least {MIN_SAMPLES}");
            return ExitCode::from(2);
        }
    };
    let source = LiveSource::new(None);
    // One read before the samples: the first read opens the host context.
    if let Err(error) = source.processes() {
        eprintln!("process_read_cost: the process table cannot be read: {error}");
        return ExitCode::FAILURE;
    }
    let mut wall: Vec<Duration> = Vec::with_capacity(samples);
    let mut cpu: Vec<Duration> = Vec::with_capacity(samples);
    let mut rows: Vec<usize> = Vec::with_capacity(samples);
    for _ in 0..samples {
        std::thread::sleep(Duration::from_millis(500));
        let (Some(cpu_before), started) = (process_cpu_time(), Instant::now()) else {
            eprintln!("process_read_cost: the CPU clock gives no value");
            return ExitCode::FAILURE;
        };
        let result = source.processes();
        let elapsed: Duration = started.elapsed();
        let Some(cpu_after) = process_cpu_time() else {
            eprintln!("process_read_cost: the CPU clock gives no value");
            return ExitCode::FAILURE;
        };
        match result {
            Ok(snapshot) => rows.push(snapshot.processes.len()),
            Err(error) => {
                eprintln!("process_read_cost: a read failed: {error}");
                return ExitCode::FAILURE;
            }
        }
        wall.push(elapsed);
        cpu.push(cpu_after.saturating_sub(cpu_before));
    }
    rows.sort_unstable();
    println!(
        "samples: {samples}; table rows in a read (at most 40): {} to {}",
        rows.first().copied().unwrap_or(0),
        rows.last().copied().unwrap_or(0)
    );
    summary("wall time", &mut wall);
    let median_cpu: Duration = summary("CPU time (process)", &mut cpu);
    for (name, interval) in [("2 s", 2.0), ("30 s", 30.0)] {
        println!(
            "median CPU time per interval of {name}: {:.3} % of one core",
            median_cpu.as_secs_f64() / interval * 100.0
        );
    }
    ExitCode::SUCCESS
}
