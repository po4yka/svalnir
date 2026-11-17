//! The native memory-pressure state as a one-shot query.
//!
//! `docs/RESOURCE_MODEL.md` section 10 owns the metric. The value comes from
//! one synchronous read of `kern.memorystatus_vm_pressure_level`. A level
//! that the adapter does not know is an unavailable reading. It is never
//! `critical`, and a failed read is never `normal`.

use svalnir_core::observation::{
    MetricKind, Observation, Reading, Sample, UnavailableReason, Unit, metric,
};
use svalnir_core::state::PressureState;

use super::context::{CollectError, CollectionContext, MetricSpec, Provenance};
use super::native;

/// The native API that the one-shot query calls.
pub const PRESSURE_NATIVE_API: &str = "sysctlbyname";
/// The native field of the one-shot query.
pub const PRESSURE_NATIVE_FIELD: &str = "kern.memorystatus_vm_pressure_level";

// The sysctl gives the level in the encoding of the memory-pressure
// notifications (`NOTE_MEMORYSTATUS_PRESSURE_*` of `sys/event.h`, the same
// numbers as `DISPATCH_MEMORYPRESSURE_*`). It is not the 0-to-3 numbering of
// the kernel type `vm_pressure_level_t`.
/// `NOTE_MEMORYSTATUS_PRESSURE_NORMAL`.
const LEVEL_NORMAL: i32 = 1;
/// `NOTE_MEMORYSTATUS_PRESSURE_WARN`.
const LEVEL_WARNING: i32 = 2;
/// `NOTE_MEMORYSTATUS_PRESSURE_CRITICAL`.
const LEVEL_CRITICAL: i32 = 4;

/// Maps a native pressure level to a state.
///
/// # Errors
///
/// Returns [`UnavailableReason::InconsistentData`] for a level that is not
/// one of the three known levels.
pub fn pressure_state_from_level(level: i32) -> Result<PressureState, UnavailableReason> {
    match level {
        LEVEL_NORMAL => Ok(PressureState::Normal),
        LEVEL_WARNING => Ok(PressureState::Warning),
        LEVEL_CRITICAL => Ok(PressureState::Critical),
        _ => Err(UnavailableReason::InconsistentData),
    }
}

/// Makes the `memory.pressure` observation from a raw level.
pub fn pressure_observation(
    context: &CollectionContext,
    level: Result<i32, UnavailableReason>,
    sample: &Sample,
) -> Observation<PressureState> {
    let reading: Reading<PressureState> = match level.and_then(pressure_state_from_level) {
        Ok(state) => Reading::Available(state),
        Err(reason) => Reading::Unavailable(reason),
    };
    context.observation(
        MetricSpec::new(metric::MEMORY_PRESSURE, Unit::State, MetricKind::State),
        context.host_scope(),
        reading,
        Provenance {
            adapter: &context.adapters.sysctl,
            native_api: PRESSURE_NATIVE_API,
            native_field: PRESSURE_NATIVE_FIELD,
        },
        sample,
    )
}

/// Reads the native memory-pressure state of the host one time.
///
/// The observation is a fresh synchronous measurement (a poll). It is
/// independent of the events of [`super::event`].
///
/// # Errors
///
/// Returns a [`CollectError`] when the clock gives no acquisition window. A
/// failed pressure query is an unavailable reading, not an error.
pub fn collect_pressure(
    context: &CollectionContext,
) -> Result<Observation<PressureState>, CollectError> {
    let acquisition = context.begin()?;
    let level: Result<i32, UnavailableReason> = native::pressure_level();
    let sample: Sample = context.finish(acquisition)?;
    Ok(pressure_observation(context, level, &sample))
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::{
        Coverage, MetricKind, ScopeKind, UnavailableReason, Unit, metric,
    };
    use svalnir_core::state::PressureState;

    use super::super::context::testing;
    #[cfg(target_os = "macos")]
    use super::collect_pressure;
    use super::{pressure_observation, pressure_state_from_level};

    #[test]
    fn each_known_level_maps_to_its_state() {
        assert_eq!(pressure_state_from_level(1), Ok(PressureState::Normal));
        assert_eq!(pressure_state_from_level(2), Ok(PressureState::Warning));
        assert_eq!(pressure_state_from_level(4), Ok(PressureState::Critical));
    }

    #[test]
    fn an_unknown_level_is_not_a_state() {
        for level in [0, 3, 5, 6, 7, 8, 16, -1, i32::MAX, i32::MIN] {
            assert_eq!(
                pressure_state_from_level(level),
                Err(UnavailableReason::InconsistentData),
                "{level}"
            );
        }
    }

    #[test]
    fn the_observation_has_the_registered_envelope() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let observation = pressure_observation(&context, Ok(2), &sample);
        assert_eq!(observation.metric_id, metric::MEMORY_PRESSURE);
        assert_eq!(observation.scope.kind, ScopeKind::Host);
        assert_eq!(observation.unit, Unit::State);
        assert_eq!(observation.kind, MetricKind::State);
        assert_eq!(observation.coverage, Coverage::Complete);
        assert_eq!(observation.value(), Some(&PressureState::Warning));
        assert_eq!(observation.source.adapter_id.as_str(), "macos.sysctl");
        assert_eq!(
            observation.source.native_field,
            "kern.memorystatus_vm_pressure_level"
        );
        assert_eq!(observation.sample, sample);
        // The envelope encodes: the unit agrees with the value type.
        serde_json::to_string(&observation).unwrap();
    }

    #[test]
    fn a_failed_or_unknown_query_is_unavailable_and_not_normal() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let denied =
            pressure_observation(&context, Err(UnavailableReason::PermissionDenied), &sample);
        assert_eq!(denied.value(), None);
        assert_eq!(denied.reason(), Some(&UnavailableReason::PermissionDenied));
        assert_eq!(denied.coverage, Coverage::Unknown);

        let unknown = pressure_observation(&context, Ok(3), &sample);
        assert_eq!(unknown.value(), None);
        assert_eq!(unknown.reason(), Some(&UnavailableReason::InconsistentData));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_host_query_gives_a_known_state_or_a_reason() {
        let context = super::CollectionContext::for_current_process().unwrap();
        let observation = collect_pressure(&context).unwrap();
        match observation.value() {
            Some(state) => assert!(state.is_recognized()),
            None => assert!(observation.reason().is_some()),
        }
        assert!(observation.sample.acquisition_duration().is_some());
    }
}
