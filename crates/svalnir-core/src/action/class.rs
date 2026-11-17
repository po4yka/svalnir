//! Action classes and trigger classes.
//!
//! `docs/ACTION_CONTRACTS.md` section 1 owns the action classes. Section 3
//! owns the trigger of a request, and section 12 owns the limits of the
//! critical-memory exception.

use crate::encoding::wire_enum;

wire_enum! {
    /// One class of mutation. The serialized spelling is the name in the
    /// specification.
    ///
    /// A class that this build does not recognize is in no family: each
    /// predicate of this type returns `false` for it, and no trigger can
    /// select it.
    ActionClass {
        /// Move explicitly selected entries to Trash.
        MoveToTrash => "MoveToTrash",
        /// Permanently remove explicitly selected entries of the user.
        DeleteSelectedFiles => "DeleteSelectedFiles",
        /// Permanently remove candidates that a reviewed cleanup rule
        /// selected.
        EvictRegenerableData => "EvictRegenerableData",
        /// Ask a verified application or managed job to exit gracefully.
        RequestApplicationExit => "RequestApplicationExit",
        /// Force a verified application or managed job to exit.
        ForceApplicationExit => "ForceApplicationExit",
    }
}

impl ActionClass {
    /// Each class that this build knows, in the sequence of the
    /// specification.
    pub const ALL: [Self; 5] = [
        Self::MoveToTrash,
        Self::DeleteSelectedFiles,
        Self::EvictRegenerableData,
        Self::RequestApplicationExit,
        Self::ForceApplicationExit,
    ];

    /// Whether the class changes the filesystem. A filesystem class always
    /// needs durable recording.
    pub fn is_filesystem(&self) -> bool {
        matches!(
            self,
            Self::MoveToTrash | Self::DeleteSelectedFiles | Self::EvictRegenerableData
        )
    }

    /// Whether the class removes data permanently.
    pub fn is_permanent_removal(&self) -> bool {
        matches!(self, Self::DeleteSelectedFiles | Self::EvictRegenerableData)
    }

    /// Whether the class is a step of an application intervention.
    pub fn is_application_intervention(&self) -> bool {
        matches!(
            self,
            Self::RequestApplicationExit | Self::ForceApplicationExit
        )
    }

    /// Whether a trigger of class `trigger` can select this action class.
    ///
    /// `MoveToTrash` and `DeleteSelectedFiles` are manual only. An automatic
    /// disk incident selects only `EvictRegenerableData`, and an automatic
    /// memory trigger selects only an application intervention. A value that
    /// this build does not recognize gives `false`.
    pub fn accepts_trigger(&self, trigger: &TriggerClass) -> bool {
        match trigger {
            TriggerClass::Manual => self.is_recognized(),
            TriggerClass::DiskPressure => matches!(self, Self::EvictRegenerableData),
            TriggerClass::GlobalCriticalMemory | TriggerClass::ApplicationBudget => {
                self.is_application_intervention()
            }
            TriggerClass::Unrecognized(_) => false,
        }
    }
}

wire_enum! {
    /// The original trigger class of a plan. An operation keeps the class
    /// of its plan: a budget-triggered operation cannot become a
    /// critical-memory operation during execution.
    TriggerClass {
        /// A person approved the plan.
        Manual => "manual",
        /// An automatic disk incident.
        DiskPressure => "disk_pressure",
        /// Sustained global critical memory pressure.
        GlobalCriticalMemory => "global_critical_memory",
        /// A sustained application-budget violation.
        ApplicationBudget => "application_budget",
    }
}

impl TriggerClass {
    /// Whether the trigger is a standing automatic policy. A value that this
    /// build does not recognize gives `false`; it is also not manual.
    pub fn is_automatic(&self) -> bool {
        matches!(
            self,
            Self::DiskPressure | Self::GlobalCriticalMemory | Self::ApplicationBudget
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ActionClass, TriggerClass};

    #[test]
    fn each_class_has_the_spelling_of_the_specification() {
        let spellings = [
            "MoveToTrash",
            "DeleteSelectedFiles",
            "EvictRegenerableData",
            "RequestApplicationExit",
            "ForceApplicationExit",
        ];
        for (class, text) in ActionClass::ALL.iter().zip(spellings) {
            let json = format!("\"{text}\"");
            assert_eq!(serde_json::to_string(class).unwrap(), json);
            assert_eq!(&serde_json::from_str::<ActionClass>(&json).unwrap(), class);
        }
    }

    #[test]
    fn an_unknown_class_is_in_no_family() {
        let class: ActionClass = serde_json::from_str("\"EmptyTrash\"").unwrap();
        assert!(!class.is_recognized());
        assert!(!class.is_filesystem());
        assert!(!class.is_permanent_removal());
        assert!(!class.is_application_intervention());
        assert!(!class.accepts_trigger(&TriggerClass::Manual));
        assert_eq!(serde_json::to_string(&class).unwrap(), "\"EmptyTrash\"");
        assert!(!ActionClass::from_wire("movetotrash").is_recognized());
    }

    #[test]
    fn the_families_are_disjoint() {
        for class in &ActionClass::ALL {
            assert_ne!(class.is_filesystem(), class.is_application_intervention());
        }
        assert!(!ActionClass::MoveToTrash.is_permanent_removal());
        assert!(ActionClass::DeleteSelectedFiles.is_permanent_removal());
        assert!(ActionClass::EvictRegenerableData.is_permanent_removal());
    }

    #[test]
    fn a_trigger_selects_only_its_classes() {
        use ActionClass::{
            DeleteSelectedFiles, EvictRegenerableData, ForceApplicationExit, MoveToTrash,
            RequestApplicationExit,
        };
        for class in &ActionClass::ALL {
            assert!(class.accepts_trigger(&TriggerClass::Manual));
        }
        let disk = TriggerClass::DiskPressure;
        assert!(EvictRegenerableData.accepts_trigger(&disk));
        for class in [
            MoveToTrash,
            DeleteSelectedFiles,
            RequestApplicationExit,
            ForceApplicationExit,
        ] {
            assert!(!class.accepts_trigger(&disk), "{class}");
        }
        for trigger in [
            TriggerClass::GlobalCriticalMemory,
            TriggerClass::ApplicationBudget,
        ] {
            assert!(RequestApplicationExit.accepts_trigger(&trigger));
            assert!(ForceApplicationExit.accepts_trigger(&trigger));
            for class in [MoveToTrash, DeleteSelectedFiles, EvictRegenerableData] {
                assert!(!class.accepts_trigger(&trigger), "{class}");
            }
        }
    }

    #[test]
    fn an_unknown_trigger_is_not_manual_and_not_automatic() {
        let trigger: TriggerClass = serde_json::from_str("\"thermal\"").unwrap();
        assert!(!trigger.is_recognized());
        assert!(!trigger.is_automatic());
        assert_ne!(trigger, TriggerClass::Manual);
        for class in &ActionClass::ALL {
            assert!(!class.accepts_trigger(&trigger));
        }
        assert!(!TriggerClass::Manual.is_automatic());
        assert!(TriggerClass::DiskPressure.is_automatic());
    }
}
