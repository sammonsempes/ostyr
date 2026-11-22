mod common;


use agent_command::action::{valid_session_id, valid_shell_reference, valid_shell_subject};
use agent_command::model::{
    MAX_REFERENCE_BYTES as AGENT_REFERENCE_BYTES, MAX_SESSION_ID_BYTES, MAX_SHELL_APPROVERS, MAX_SHELL_IDLE_SECONDS, MAX_SHELL_SECONDS,
    MAX_SUBJECT_BYTES as AGENT_SUBJECT_BYTES,
};
use common::types::TestResult;
use remote_shell::grammar::{valid_reference, valid_subject, MAX_REFERENCE_BYTES, MAX_SUBJECT_BYTES};
use remote_shell::open::MAX_APPROVALS;
use remote_shell::policy::{CEILING_IDLE_TIMEOUT_SECONDS, CEILING_MAX_DURATION_SECONDS};


const EDGE_INPUTS: [&str; 14] = [
    "",
    "a",
    "a/b",
    "a:b",
    "-x",
    "_x",
    ".x",
    "a\0b",
    "a\u{3164}b",
    "caf\u{e9}",
    "a b",
    "a|b",
    "a@b=c+d",
    "A9_.-/:",
];


#[test]
fn the_ceilings_and_caps_equal_remote_shell() -> TestResult {
    assert_eq!(u64::from(MAX_SHELL_SECONDS), CEILING_MAX_DURATION_SECONDS);
    assert_eq!(u64::from(MAX_SHELL_IDLE_SECONDS), CEILING_IDLE_TIMEOUT_SECONDS);
    assert_eq!(MAX_SHELL_APPROVERS, MAX_APPROVALS);
    assert_eq!(MAX_SESSION_ID_BYTES, MAX_REFERENCE_BYTES);
    assert_eq!(AGENT_REFERENCE_BYTES, MAX_REFERENCE_BYTES);
    assert_eq!(AGENT_SUBJECT_BYTES, MAX_SUBJECT_BYTES);
    Ok(())
}


#[test]
fn the_agent_grammars_never_accept_what_remote_shell_refuses() -> TestResult {
    let long_reference = "a".repeat(MAX_REFERENCE_BYTES + 1);
    let long_subject = "a".repeat(MAX_SUBJECT_BYTES + 1);
    let exact_reference = "a".repeat(MAX_REFERENCE_BYTES);
    let exact_subject = "a".repeat(MAX_SUBJECT_BYTES);
    EDGE_INPUTS
        .iter()
        .chain(
            [
                long_reference.as_str(),
                long_subject.as_str(),
                exact_reference.as_str(),
                exact_subject.as_str(),
            ]
            .iter(),
        )
        .for_each(|text| {
            assert_eq!(valid_shell_reference(text), valid_reference(text), "{text:?}");
            assert_eq!(valid_shell_subject(text), valid_subject(text) && !text.starts_with('-'), "{text:?}");
            assert!(!valid_session_id(text) || valid_reference(text), "{text:?}");
            assert!(!valid_session_id(text) || (!text.contains('/') && !text.contains(':')), "{text:?}");
        });
    Ok(())
}
