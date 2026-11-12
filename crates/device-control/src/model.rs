use crate::error::ValidationError;
use crate::limits::{CLASS_DIGITS, ID_DIGITS};
use crate::types::InterfaceTriple;
use crate::validate::{is_lower_hex, is_owner, is_reason_forbidden, is_serial, is_too_long_reason};
use serde::Deserialize;
use time::OffsetDateTime;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Audit,
    Enforce,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct ClassCode(pub String);


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct UsbId(pub String);


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Serial(pub String);


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Owner(pub String);


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Reason(pub String);


impl TryFrom<String> for ClassCode {
    type Error = ValidationError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if is_lower_hex(&text, CLASS_DIGITS) {
            Ok(Self(text))
        } else {
            Err(ValidationError::Hex { length: CLASS_DIGITS })
        }
    }
}


impl TryFrom<String> for UsbId {
    type Error = ValidationError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if is_lower_hex(&text, ID_DIGITS) {
            Ok(Self(text))
        } else {
            Err(ValidationError::Hex { length: ID_DIGITS })
        }
    }
}


impl TryFrom<String> for Serial {
    type Error = ValidationError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if is_serial(&text) {
            Ok(Self(text))
        } else {
            Err(ValidationError::Serial)
        }
    }
}


impl TryFrom<String> for Owner {
    type Error = ValidationError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if is_owner(&text) {
            Ok(Self(text))
        } else {
            Err(ValidationError::Owner)
        }
    }
}


impl TryFrom<String> for Reason {
    type Error = ValidationError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if is_too_long_reason(&text) {
            Err(ValidationError::ReasonTooLong)
        } else if text.chars().any(is_reason_forbidden) {
            Err(ValidationError::ReasonForbidden)
        } else {
            Ok(Self(text))
        }
    }
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub action: Action,
    pub class: Option<ClassCode>,
    pub vendor: Option<UsbId>,
    pub product: Option<UsbId>,
    pub serial: Option<Serial>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawRule")]
pub struct Rule {
    pub action: Action,
    pub class: Option<ClassCode>,
    pub vendor: Option<UsbId>,
    pub product: Option<UsbId>,
    pub serial: Option<Serial>,
}


impl TryFrom<RawRule> for Rule {
    type Error = ValidationError;

    fn try_from(raw: RawRule) -> Result<Self, Self::Error> {
        let has_matcher = raw.class.is_some() || raw.vendor.is_some() || raw.product.is_some();
        if !has_matcher {
            Err(ValidationError::NoMatcher)
        } else if raw.serial.is_some() && raw.action == Action::Block {
            Err(ValidationError::SerialOnBlock)
        } else {
            Ok(Self {
                action: raw.action,
                class: raw.class,
                vendor: raw.vendor,
                product: raw.product,
                serial: raw.serial,
            })
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub rule: Rule,
    pub owner: Owner,
    #[serde(with = "time::serde::rfc3339")]
    pub expires: OffsetDateTime,
    pub reason: Reason,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub mode: Mode,
    pub default: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub exceptions: Vec<Exception>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDevice {
    pub vendor: String,
    pub product: String,
    pub serial: Option<String>,
    pub interfaces: Vec<InterfaceTriple>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matched {
    Exception(usize),
    Rule(usize),
    Default,
    Oversized,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow { rule: Matched },
    Block { rule: Matched },
    Audit { would: Action, rule: Matched },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFile {
    pub rules: String,
    pub implicit_target: Action,
}
