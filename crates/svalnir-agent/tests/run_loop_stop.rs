//! The stop request of the main run loop that is not a signal.
//!
//! This program has its own `main`, because the main run loop runs only on
//! the main thread of a process. It sends no signal, registers no service,
//! and changes no file.
//!
//! The stop is recorded one time for the life of the process, so the
//! program has one sequence: a request that arrives while the run loop
//! waits, then a run loop that starts after a request.

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    use svalnir_agent::platform::run_loop::{
        StopSignal, request_main_run_loop_stop, run_main_run_loop_until_stop,
    };

    // A run loop that does not end fails the test and does not hang it.
    let _watchdog = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(20));
        eprintln!("the main run loop did not end at the stop request");
        std::process::exit(2);
    });

    // The request arrives from another thread while the run loop waits,
    // as at the early end of the service of the agent.
    let started: Instant = Instant::now();
    let requester = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(300));
        request_main_run_loop_stop();
    });
    let stopped = run_main_run_loop_until_stop();
    if stopped != Ok(StopSignal::Requested) {
        eprintln!("the run loop ended with {stopped:?}");
        return ExitCode::FAILURE;
    }
    if started.elapsed() < Duration::from_millis(250) {
        eprintln!("the run loop ended before the stop request");
        return ExitCode::FAILURE;
    }
    if requester.join().is_err() {
        return ExitCode::FAILURE;
    }

    // A run loop that starts after the request returns before its first
    // wait.
    let started: Instant = Instant::now();
    let again = run_main_run_loop_until_stop();
    if again != Ok(StopSignal::Requested) || started.elapsed() > Duration::from_secs(5) {
        eprintln!("a run loop after the request ended with {again:?}");
        return ExitCode::FAILURE;
    }
    println!("the main run loop ends at a stop request that is not a signal: ok");
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn main() {
    // This host has no main run loop that Svalnir uses.
}
