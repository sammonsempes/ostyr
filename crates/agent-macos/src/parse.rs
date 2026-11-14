use crate::error::ParseError;
use crate::model::Posture;
use crate::types::Forms;


/// Largest tool output a parser accepts.
pub const MAX_OUTPUT_BYTES: usize = 4096;


pub const REASON_EMPTY: &str = "empty output";


pub const REASON_UNRECOGNISED: &str = "output not in a known form";


pub const REASON_NOT_READ: &str = "not read in this slice";


pub const REASON_TOO_LARGE: &str = "output too large";


pub const FILEVAULT_FORMS: Forms<'static> = &[("FileVault is On.", Posture::Enabled), ("FileVault is Off.", Posture::Disabled)];


pub const GATEKEEPER_FORMS: Forms<'static> = &[("assessments enabled", Posture::Enabled), ("assessments disabled", Posture::Disabled)];


pub const SIP_FORMS: Forms<'static> = &[
    ("System Integrity Protection status: enabled.", Posture::Enabled),
    ("System Integrity Protection status: disabled.", Posture::Disabled),
];


pub const FIREWALL_FORMS: Forms<'static> = &[
    ("Firewall is enabled. (State = 1)", Posture::Enabled),
    ("Firewall is disabled. (State = 0)", Posture::Disabled),
];


/// Matches the whole output, trailing whitespace removed, against the exact known forms.
pub fn classify(output: &str, forms: Forms) -> Result<Posture, ParseError> {
    let length = output.len();
    let trimmed = output.trim_end();
    let found = forms.iter().find(|(text, _)| *text == trimmed).map(|(_, posture)| *posture);
    let posture = match (trimmed.is_empty(), found) {
        (true, _) => Posture::Unknown { reason: REASON_EMPTY },
        (false, Some(known)) => known,
        (false, None) => Posture::Unknown { reason: REASON_UNRECOGNISED },
    };
    match length > MAX_OUTPUT_BYTES {
        true => Err(ParseError::TooLarge {
            length,
            limit: MAX_OUTPUT_BYTES,
        }),
        false => Ok(posture),
    }
}


pub fn parse_filevault(output: &str) -> Result<Posture, ParseError> {
    classify(output, FILEVAULT_FORMS)
}


pub fn parse_gatekeeper(output: &str) -> Result<Posture, ParseError> {
    classify(output, GATEKEEPER_FORMS)
}


pub fn parse_sip(output: &str) -> Result<Posture, ParseError> {
    classify(output, SIP_FORMS)
}


pub fn parse_firewall(output: &str) -> Result<Posture, ParseError> {
    classify(output, FIREWALL_FORMS)
}
