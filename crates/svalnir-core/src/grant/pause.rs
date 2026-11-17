//! Pause and resume of automatic intervention.
//!
//! `docs/POLICY_SPEC.md` section 14 owns the pause. A pause inhibits new
//! automatic dispatch, the next escalation, and the next batch. It does not
//! stop monitoring, it does not recall a submitted request, and it does not
//! apply to a manual action that has its own approval.
//!
//! The scope of a pause in this module is all automation of the user, which
//! is the scope of `agent pause`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::state::{AuthorityState, Change, Fallback, InstanceInhibition, Settled};
use crate::id::{BootId, ClockDomainId};
use crate::policy::EvaluationClock;
use crate::process::Uid;
use crate::quantity::Nanoseconds;
use crate::time::{MonotonicNanos, WallTime};

const NANOSECONDS_PER_SECOND: u128 = 1_000_000_000;

/// The time of a control request. The caller reads the two clocks.
#[derive(Debug, Clone, Copy)]
pub struct ControlClock<'a> {
    /// The monotonic time, its clock domain, and its boot.
    pub clock: &'a EvaluationClock,
    /// The wall-clock time.
    pub wall: WallTime,
}

/// The expiry of a timed pause, in monotonic and in wall-clock terms.
///
/// In the boot and the clock domain of the pause, only the monotonic time
/// decides. In a different boot the monotonic time has no meaning, and the
/// wall-clock time decides.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PauseDeadline {
    /// The monotonic time at which the pause ends.
    pub monotonic: MonotonicNanos,
    /// The clock domain of `monotonic`.
    pub clock_domain: ClockDomainId,
    /// The boot of `monotonic`.
    pub boot_id: BootId,
    /// The wall-clock time at which the pause ends.
    pub wall: WallTime,
}

/// A pause of each automatic intervention of the user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pause {
    /// The wall-clock time of the request, for history only.
    pub started_wall: WallTime,
    /// The expiry. `None` means that the pause applies until a resume.
    pub deadline: Option<PauseDeadline>,
}

impl Pause {
    /// The pause that inhibits for the longer time. A pause with no expiry
    /// is the longer one; two timed pauses are compared by their wall-clock
    /// expiry.
    pub(super) fn longer(left: Self, right: Self) -> Self {
        match (&left.deadline, &right.deadline) {
            (None, _) => left,
            (_, None) => right,
            (Some(first), Some(second)) => {
                // On one monotonic timeline, the monotonic expiry decides,
                // as it does for the status of the pause.
                let same_timeline: bool =
                    first.clock_domain == second.clock_domain && first.boot_id == second.boot_id;
                let second_is_later: bool = if same_timeline {
                    second.monotonic > first.monotonic
                } else {
                    second.wall > first.wall
                };
                if second_is_later { right } else { left }
            }
        }
    }
}

/// The time of a resume or of a pause expiry. An automatic action after it
/// needs a measurement that is not older (`README.md`, "Enable continuous
/// protection": a resume always refreshes the measurements).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct MeasurementFloor {
    /// The monotonic time.
    pub at: MonotonicNanos,
    /// The clock domain of `at`.
    pub clock_domain: ClockDomainId,
    /// The boot of `at`.
    pub boot_id: BootId,
}

/// What decided the status of a pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseBasis {
    /// The pause has no expiry.
    Indefinite,
    /// The monotonic time of the boot of the pause.
    Monotonic,
    /// The wall-clock time, because the pause is from a different boot or
    /// clock domain.
    WallClock,
}

/// The status of a pause at one time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PauseStatus {
    /// There is no pause.
    NotPaused,
    /// The pause inhibits automatic intervention.
    Paused {
        /// The time that remains. `None` when the pause has no expiry, or
        /// when the time is larger than the largest quantity.
        remaining: Option<Nanoseconds>,
        /// The wall-clock expiry. `None` when the pause has no expiry.
        until: Option<WallTime>,
        /// What decided the status.
        basis: PauseBasis,
    },
    /// The pause is at its expiry or after it. It inhibits nothing. The
    /// next automatic action needs a measurement that is not older than
    /// the expiry.
    Expired {
        /// The expiry on the monotonic timeline of the request. When the
        /// wall-clock time decided, this is the time of the request less
        /// the wall-clock time since the expiry. `None` when the pause
        /// ended before that timeline started: each measurement of the
        /// current boot is then newer.
        floor: Option<MonotonicNanos>,
        /// What decided the status.
        basis: PauseBasis,
    },
}

impl PauseStatus {
    /// Whether the pause inhibits automatic intervention.
    pub const fn is_paused(&self) -> bool {
        matches!(self, Self::Paused { .. })
    }
}

/// The wall-clock time `duration` after `start`. `None` when the result is
/// not a time that [`WallTime`] can hold.
fn wall_after(start: WallTime, duration: Nanoseconds) -> Option<WallTime> {
    let total: u128 =
        u128::from(start.subsecond_nanoseconds()).checked_add(u128::from(duration.get()))?;
    let seconds: i64 = i64::try_from(total / NANOSECONDS_PER_SECOND).ok()?;
    let fraction: u32 = u32::try_from(total % NANOSECONDS_PER_SECOND).ok()?;
    let unix_seconds: i64 = start.unix_seconds().checked_add(seconds)?;
    WallTime::from_unix(unix_seconds, fraction).ok()
}

/// The time from `now` to `later`. `None` when `later` is before `now`, or
/// when the time is larger than the largest quantity.
fn wall_between(now: WallTime, later: WallTime) -> Option<Nanoseconds> {
    let seconds: i128 = i128::from(later.unix_seconds()) - i128::from(now.unix_seconds());
    let fraction: i128 =
        i128::from(later.subsecond_nanoseconds()) - i128::from(now.subsecond_nanoseconds());
    let total: i128 = seconds.checked_mul(1_000_000_000)?.checked_add(fraction)?;
    u64::try_from(total).ok().map(Nanoseconds::new)
}

/// The status of `pause` at `clock`.
///
/// A timed pause is expired at its expiry time and after it. In the boot
/// and the clock domain of the pause, the monotonic time decides, and a
/// change of the wall clock has no effect. In a different boot or clock
/// domain, the wall-clock time decides: the pause stays until the wall
/// clock is at the recorded expiry, so a restart does not end a pause
/// early. A pause with no expiry stays until a resume.
pub fn pause_status(pause: Option<&Pause>, clock: &ControlClock<'_>) -> PauseStatus {
    let Some(pause) = pause else {
        return PauseStatus::NotPaused;
    };
    let Some(deadline) = &pause.deadline else {
        return PauseStatus::Paused {
            remaining: None,
            until: None,
            basis: PauseBasis::Indefinite,
        };
    };
    let same_timeline: bool = deadline.clock_domain == clock.clock.clock_domain
        && deadline.boot_id == clock.clock.boot_id;
    if same_timeline {
        return match deadline.monotonic.checked_duration_since(clock.clock.now) {
            Some(remaining) if remaining > Nanoseconds::ZERO => PauseStatus::Paused {
                remaining: Some(remaining),
                until: Some(deadline.wall),
                basis: PauseBasis::Monotonic,
            },
            _ => PauseStatus::Expired {
                floor: Some(deadline.monotonic),
                basis: PauseBasis::Monotonic,
            },
        };
    }
    if clock.wall < deadline.wall {
        PauseStatus::Paused {
            remaining: wall_between(clock.wall, deadline.wall),
            until: Some(deadline.wall),
            basis: PauseBasis::WallClock,
        }
    } else {
        // The pause can have ended in the current boot. Its expiry is
        // then the time since the wall-clock expiry before `now`. When
        // that time is before the start of the monotonic timeline, each
        // measurement of the current boot is newer.
        let floor: Option<MonotonicNanos> = wall_between(deadline.wall, clock.wall)
            .and_then(|elapsed| clock.clock.now.get().checked_sub(elapsed.get()))
            .map(MonotonicNanos::new);
        PauseStatus::Expired {
            floor,
            basis: PauseBasis::WallClock,
        }
    }
}

/// A request to pause automatic intervention (`agent pause`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseRequest {
    /// The authenticated user of the request.
    pub principal: Uid,
    /// The length of the pause (`--for`). `None` asks for a pause with no
    /// expiry.
    pub duration: Option<Nanoseconds>,
}

/// The reason a pause request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PauseRefusal {
    /// The request is from a different user than the record.
    #[error("the request is from a different user than the authority record")]
    WrongPrincipal,
    /// The length of the pause is zero.
    #[error("the length of the pause is zero")]
    ZeroDuration,
    /// The expiry is not a time that the clocks can hold.
    #[error("the expiry of the pause is out of range")]
    DeadlineOutOfRange,
}

/// The report of a pause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PauseReport {
    /// The pause that the record now has.
    pub pause: Pause,
    /// The pause that the request replaced.
    pub replaced: Option<Pause>,
}

/// Pauses each automatic intervention of the user.
///
/// A pause replaces an earlier pause of the record. The change is a
/// restriction: when it cannot be persisted, the running instance keeps the
/// pause in its volatile state.
///
/// # Errors
///
/// Returns a [`PauseRefusal`] when the user is not the user of the record,
/// when the length is zero, or when the expiry is out of range.
pub fn pause(
    state: &AuthorityState,
    request: &PauseRequest,
    clock: &ControlClock<'_>,
) -> Result<Change<PauseReport>, PauseRefusal> {
    if request.principal != state.principal {
        return Err(PauseRefusal::WrongPrincipal);
    }
    let deadline: Option<PauseDeadline> = match request.duration {
        None => None,
        Some(duration) if duration == Nanoseconds::ZERO => {
            return Err(PauseRefusal::ZeroDuration);
        }
        Some(duration) => Some(PauseDeadline {
            monotonic: clock
                .clock
                .now
                .checked_add(duration)
                .ok_or(PauseRefusal::DeadlineOutOfRange)?,
            clock_domain: clock.clock.clock_domain.clone(),
            boot_id: clock.clock.boot_id.clone(),
            wall: wall_after(clock.wall, duration).ok_or(PauseRefusal::DeadlineOutOfRange)?,
        }),
    };
    let new_pause: Pause = Pause {
        started_wall: clock.wall,
        deadline,
    };
    let mut next: AuthorityState = state.clone();
    let replaced: Option<Pause> = next.pause.replace(new_pause.clone());
    let report: PauseReport = PauseReport {
        pause: new_pause.clone(),
        replaced,
    };
    let on_failure: Fallback = Fallback {
        guards: Vec::new(),
        pause: Some(new_pause),
    };
    // A durable pause is the latest request of the user, so it replaces a
    // pause that the instance kept after a failed write.
    let on_durable: Settled = Settled {
        clear_pause: true,
        ..Settled::default()
    };
    Ok(Change::new(state, next, report, on_failure, on_durable))
}

/// A request to resume automatic intervention (`agent resume`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeRequest {
    /// The authenticated user of the request.
    pub principal: Uid,
}

/// The reason a resume request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ResumeRefusal {
    /// The request is from a different user than the record.
    #[error("the request is from a different user than the authority record")]
    WrongPrincipal,
}

/// The report of a resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResumeReport {
    /// The durable pause that the request removes.
    pub durable_pause: Option<Pause>,
    /// The volatile pause that the request removes.
    pub volatile_pause: Option<Pause>,
    /// Always true: the next automatic action needs a measurement that is
    /// not older than `measurement_floor`.
    pub requires_fresh_measurement: bool,
    /// The time of the resume.
    pub measurement_floor: MeasurementFloor,
}

/// Resumes automatic intervention.
///
/// The change adds authority. When the record has a durable pause and the
/// write fails, nothing changes: the pause stays. When the pause is only in
/// the volatile state, there is nothing to write, and the resume applies.
/// A resume does not make an old plan valid and does not give a
/// measurement: [`ResumeReport::requires_fresh_measurement`] is true, and
/// the authorization refuses an automatic action whose evidence is older
/// than the resume.
///
/// # Errors
///
/// Returns [`ResumeRefusal::WrongPrincipal`] when the user is not the user
/// of the record.
pub fn resume(
    state: &AuthorityState,
    inhibition: &InstanceInhibition,
    request: &ResumeRequest,
    clock: &ControlClock<'_>,
) -> Result<Change<ResumeReport>, ResumeRefusal> {
    if request.principal != state.principal {
        return Err(ResumeRefusal::WrongPrincipal);
    }
    let floor: MeasurementFloor = MeasurementFloor {
        at: clock.clock.now,
        clock_domain: clock.clock.clock_domain.clone(),
        boot_id: clock.clock.boot_id.clone(),
    };
    let mut next: AuthorityState = state.clone();
    let durable_pause: Option<Pause> = next.pause.take();
    let report: ResumeReport = ResumeReport {
        durable_pause,
        volatile_pause: inhibition.pause.clone(),
        requires_fresh_measurement: true,
        measurement_floor: floor.clone(),
    };
    let on_durable: Settled = Settled {
        clear_guards: Vec::new(),
        clear_pause: true,
        floor: Some(floor),
    };
    Ok(Change::new(
        state,
        next,
        report,
        Fallback::default(),
        on_durable,
    ))
}

/// The floor that the pauses and the latest resume give for the trigger
/// evidence of an automatic action at `clock`: the latest of the resume
/// time and the monotonic expiry of each expired pause, in the boot and the
/// clock domain of `clock`. A time of a different boot gives no floor: each
/// measurement of the current boot is newer.
pub(super) fn measurement_floor(
    state: &AuthorityState,
    inhibition: &InstanceInhibition,
    clock: &ControlClock<'_>,
) -> Option<MonotonicNanos> {
    let resumed: Option<MonotonicNanos> = inhibition
        .measurement_floor
        .as_ref()
        .filter(|floor| {
            floor.clock_domain == clock.clock.clock_domain && floor.boot_id == clock.clock.boot_id
        })
        .map(|floor| floor.at);
    let expired = |pause: Option<&Pause>| match pause_status(pause, clock) {
        PauseStatus::Expired { floor, .. } => floor,
        _ => None,
    };
    [
        resumed,
        expired(state.pause.as_ref()),
        expired(inhibition.pause.as_ref()),
    ]
    .into_iter()
    .flatten()
    .max()
}
