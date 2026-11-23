//! Probe settings; exec events are off until an operator turns them on.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProbeSettings {
    pub exec_events: bool,
}
