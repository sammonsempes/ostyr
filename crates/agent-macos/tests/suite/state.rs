use agent_macos::model::{Posture, ToolOutputs};
use agent_macos::parse::{MAX_OUTPUT_BYTES, REASON_NOT_READ, REASON_TOO_LARGE};
use agent_macos::state::{blind_spots, protection_state};


const GOOD: ToolOutputs = ToolOutputs {
    fdesetup_status: "FileVault is On.\n",
    spctl_status: "assessments enabled\n",
    csrutil_status: "System Integrity Protection status: enabled.\n",
    firewall_global_state: "Firewall is disabled. (State = 0)\n",
};


#[test]
fn all_tools_read_leave_only_xprotect_blind() -> Result<(), String> {
    let state = protection_state(&GOOD);
    assert_eq!(state.filevault, Posture::Enabled);
    assert_eq!(state.gatekeeper, Posture::Enabled);
    assert_eq!(state.sip, Posture::Enabled);
    assert_eq!(state.firewall, Posture::Disabled);
    assert_eq!(state.xprotect, Posture::Unknown { reason: REASON_NOT_READ });
    assert_eq!(blind_spots(&state), vec!["xprotect"]);
    Ok(())
}


#[test]
fn unreadable_outputs_become_blind_spots() -> Result<(), String> {
    let big = "x".repeat(MAX_OUTPUT_BYTES + 1);
    let outputs = ToolOutputs {
        fdesetup_status: &big,
        spctl_status: "",
        csrutil_status: "garbage",
        firewall_global_state: &big,
    };
    let state = protection_state(&outputs);
    assert_eq!(state.filevault, Posture::Unknown { reason: REASON_TOO_LARGE });
    assert_eq!(blind_spots(&state), vec!["filevault", "gatekeeper", "sip", "firewall", "xprotect"]);
    Ok(())
}
