use agent_macos::error::ParseError;
use agent_macos::model::Posture;
use agent_macos::parse::{parse_filevault, parse_firewall, parse_gatekeeper, parse_sip, MAX_OUTPUT_BYTES, REASON_EMPTY, REASON_UNRECOGNISED};


struct Case {
    parse: fn(&str) -> Result<Posture, ParseError>,
    on: &'static str,
    off: &'static str,
    wrong_case: &'static str,
}


const UNRECOGNISED: Posture = Posture::Unknown { reason: REASON_UNRECOGNISED };


const EMPTY: Posture = Posture::Unknown { reason: REASON_EMPTY };


const SHOWN_LENGTH: usize = 5000;


const SHOWN_LIMIT: usize = 4096;


fn forms() -> Vec<Case> {
    vec![
        Case {
            parse: parse_filevault,
            on: "FileVault is On.",
            off: "FileVault is Off.",
            wrong_case: "filevault is on.",
        },
        Case {
            parse: parse_gatekeeper,
            on: "assessments enabled",
            off: "assessments disabled",
            wrong_case: "Assessments Enabled",
        },
        Case {
            parse: parse_sip,
            on: "System Integrity Protection status: enabled.",
            off: "System Integrity Protection status: disabled.",
            wrong_case: "system integrity protection status: enabled.",
        },
        Case {
            parse: parse_firewall,
            on: "Firewall is enabled. (State = 1)",
            off: "Firewall is disabled. (State = 0)",
            wrong_case: "firewall is enabled. (state = 1)",
        },
    ]
}


#[test]
fn documented_forms_are_recognised() -> Result<(), ParseError> {
    forms().iter().try_for_each(|case| {
        assert_eq!((case.parse)(case.on)?, Posture::Enabled);
        assert_eq!((case.parse)(case.off)?, Posture::Disabled);
        Ok(())
    })
}


#[test]
fn trailing_whitespace_is_accepted() -> Result<(), ParseError> {
    forms().iter().try_for_each(|case| {
        assert_eq!((case.parse)(&format!("{}\n", case.on))?, Posture::Enabled);
        assert_eq!((case.parse)(&format!("{} \r\n\n", case.off))?, Posture::Disabled);
        Ok(())
    })
}


#[test]
fn leading_whitespace_and_extra_lines_are_unknown() -> Result<(), ParseError> {
    forms().iter().try_for_each(|case| {
        assert_eq!((case.parse)(&format!(" {}", case.on))?, UNRECOGNISED);
        assert_eq!((case.parse)(&format!("{}\nmore", case.on))?, UNRECOGNISED);
        Ok(())
    })
}


#[test]
fn different_case_is_unknown() -> Result<(), ParseError> {
    forms().iter().try_for_each(|case| {
        assert_eq!((case.parse)(case.wrong_case)?, UNRECOGNISED);
        Ok(())
    })
}


#[test]
fn empty_output_is_unknown() -> Result<(), ParseError> {
    forms().iter().try_for_each(|case| {
        assert_eq!((case.parse)("")?, EMPTY);
        assert_eq!((case.parse)(" \n")?, EMPTY);
        Ok(())
    })
}


#[test]
fn sip_custom_configuration_is_unknown() -> Result<(), ParseError> {
    let output = "System Integrity Protection status: unknown (Custom Configuration).\n";
    assert_eq!(parse_sip(output)?, UNRECOGNISED);
    Ok(())
}


#[test]
fn filevault_busy_and_progress_are_unknown() -> Result<(), ParseError> {
    assert_eq!(parse_filevault("FileVault appears to be On but Busy.")?, UNRECOGNISED);
    assert_eq!(
        parse_filevault("FileVault is On.\nEncryption in progress: Percent completed = 10")?,
        UNRECOGNISED
    );
    Ok(())
}


#[test]
fn oversized_output_is_refused() -> Result<(), ParseError> {
    let big = " ".repeat(MAX_OUTPUT_BYTES + 1);
    forms().iter().try_for_each(|case| {
        assert_eq!(
            (case.parse)(&big),
            Err(ParseError::TooLarge {
                length: MAX_OUTPUT_BYTES + 1,
                limit: MAX_OUTPUT_BYTES
            })
        );
        assert!((case.parse)(&format!("{}{big}", case.on)).is_err());
        Ok(())
    })
}


#[test]
fn output_at_the_limit_is_accepted() -> Result<(), ParseError> {
    let padded = format!("FileVault is On.{}", " ".repeat(MAX_OUTPUT_BYTES - "FileVault is On.".len()));
    assert_eq!(parse_filevault(&padded)?, Posture::Enabled);
    Ok(())
}


#[test]
fn error_message_names_the_sizes() -> Result<(), ParseError> {
    let message = ParseError::TooLarge {
        length: SHOWN_LENGTH,
        limit: SHOWN_LIMIT,
    }
    .to_string();
    assert!(message.contains("5000") && message.contains("4096"));
    Ok(())
}
