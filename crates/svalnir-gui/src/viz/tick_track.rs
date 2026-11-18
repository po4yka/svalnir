//! The pressure states of the readings and the label of the pressure row of
//! the session chart.

use crate::data::model::{Measured, PressureLevel};

/// What one reading shows in the pressure row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickState {
    /// Normal pressure.
    Normal,
    /// Warning pressure.
    Warning,
    /// Critical pressure.
    Critical,
    /// An unavailable reading.
    Empty,
}

/// The state of one pressure reading; unavailable is never Normal.
#[must_use]
pub const fn state_of(pressure: &Measured<PressureLevel>) -> TickState {
    match pressure {
        Measured::Value(PressureLevel::Normal) => TickState::Normal,
        Measured::Value(PressureLevel::Warning) => TickState::Warning,
        Measured::Value(PressureLevel::Critical) => TickState::Critical,
        Measured::Unavailable(_) => TickState::Empty,
    }
}

/// The accessible label: the count of each level.
#[must_use]
pub fn track_label(states: &[TickState]) -> String {
    let count = |wanted: TickState| states.iter().filter(|s| **s == wanted).count();
    let samples: usize = states.iter().filter(|s| **s != TickState::Empty).count();
    format!(
        "Pressure history: {samples} measured samples, {} normal, {} warning, {} critical",
        count(TickState::Normal),
        count(TickState::Warning),
        count(TickState::Critical)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_is_empty_not_normal() {
        assert_eq!(
            state_of(&Measured::Unavailable("x".into())),
            TickState::Empty
        );
        assert_eq!(
            state_of(&Measured::Value(PressureLevel::Normal)),
            TickState::Normal
        );
    }

    #[test]
    fn the_label_counts_only_measured_samples() {
        let states = [
            TickState::Empty,
            TickState::Normal,
            TickState::Empty,
            TickState::Critical,
        ];
        let label = track_label(&states);
        assert!(label.contains("2 measured samples"), "{label}");
        assert!(
            label.contains("1 normal") && label.contains("1 critical"),
            "{label}"
        );
    }
}
