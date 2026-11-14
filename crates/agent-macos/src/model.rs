/// State of one protection, never a guess: anything not recognised exactly is `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    Enabled,
    Disabled,
    Unknown { reason: &'static str },
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionState {
    pub filevault: Posture,
    pub gatekeeper: Posture,
    pub sip: Posture,
    pub firewall: Posture,
    pub xprotect: Posture,
}


/// Standard output of each tool, already read by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolOutputs<'a> {
    pub fdesetup_status: &'a str,
    pub spctl_status: &'a str,
    pub csrutil_status: &'a str,
    pub firewall_global_state: &'a str,
}
