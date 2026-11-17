//! State enumerations that more than one component reads.
//!
//! `docs/RESOURCE_MODEL.md` sections 10 and 13 own these states. A value that
//! this build does not recognize stays `Unrecognized`. It is never read as
//! `normal` or `available`.

use crate::encoding::wire_enum;

wire_enum! {
    /// The native memory-pressure state of the host: the value of the
    /// `memory.pressure` metric.
    ///
    /// High memory use, swap use, or a native flag that the adapter does not
    /// know is not a pressure state.
    PressureState {
        /// No memory pressure.
        Normal => "normal",
        /// The system reports a warning.
        Warning => "warning",
        /// The system reports critical pressure.
        Critical => "critical",
    }
}

wire_enum! {
    /// Whether a worker can do one operation on one resource.
    ///
    /// The state is independent of the availability of one observation. A
    /// read capability does not authorize deletion or signaling.
    CapabilityState {
        /// A probe of the intended operation succeeded.
        Available => "available",
        /// The system or the user denied the operation.
        Denied => "denied",
        /// The host or the source does not support the operation.
        Unsupported => "unsupported",
        /// No probe result is known.
        Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{CapabilityState, PressureState};

    #[test]
    fn each_state_round_trips() {
        for (state, text) in [
            (PressureState::Normal, "\"normal\""),
            (PressureState::Warning, "\"warning\""),
            (PressureState::Critical, "\"critical\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), text);
            assert_eq!(serde_json::from_str::<PressureState>(text).unwrap(), state);
        }
        for (state, text) in [
            (CapabilityState::Available, "\"available\""),
            (CapabilityState::Denied, "\"denied\""),
            (CapabilityState::Unsupported, "\"unsupported\""),
            (CapabilityState::Unknown, "\"unknown\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), text);
            assert_eq!(
                serde_json::from_str::<CapabilityState>(text).unwrap(),
                state
            );
        }
    }

    #[test]
    fn an_unknown_state_is_not_a_known_state() {
        let pressure: PressureState = serde_json::from_str("\"urgent\"").unwrap();
        assert!(!pressure.is_recognized());
        assert_ne!(pressure, PressureState::Normal);
        assert_eq!(serde_json::to_string(&pressure).unwrap(), "\"urgent\"");
        // The spelling is exact: a different case is a different value.
        assert!(!PressureState::from_wire("Normal").is_recognized());

        let capability: CapabilityState = serde_json::from_str("\"restricted\"").unwrap();
        assert!(!capability.is_recognized());
        assert_ne!(capability, CapabilityState::Unknown);
        assert_ne!(capability, CapabilityState::Available);

        assert!(serde_json::from_str::<PressureState>("0").is_err());
        assert!(serde_json::from_str::<PressureState>("null").is_err());
    }
}
