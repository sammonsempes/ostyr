use siem_ingest::tenant::is_tenant_char;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;


pub const MESSAGE_ID_PARTS: usize = 4;


pub const ID_SEPARATOR: char = ':';


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityRefusal {
    MissingId,
    RepeatedId,
    WrongPartCount,
    WrongTenant,
    BadAgent,
    BadSequence,
    BadIndex,
    NoStoredTime,
}


impl Display for IdentityRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(match self {
            Self::MissingId => "no_message_id",
            Self::RepeatedId => "repeated_message_id",
            Self::WrongPartCount => "wrong_part_count",
            Self::WrongTenant => "tenant_mismatch",
            Self::BadAgent => "bad_agent_id",
            Self::BadSequence => "bad_sequence",
            Self::BadIndex => "bad_index",
            Self::NoStoredTime => "no_stored_time",
        })
    }
}


/// A number written the one canonical way: no sign, no leading zero, no space.
pub fn is_canonical<Number: FromStr + Display>(text: &str) -> bool {
    text.parse::<Number>().is_ok_and(|number| number.to_string() == text)
}


pub fn is_agent_id(text: &str, max_bytes: usize) -> bool {
    !text.is_empty() && text.len() <= max_bytes && text.chars().all(is_tenant_char)
}


/// The single `Nats-Msg-Id` value, which only the event gateway writes, from the client certificate: the payload never takes part.
pub fn single_id(message_ids: &[String]) -> Result<&str, IdentityRefusal> {
    match message_ids {
        [] => Err(IdentityRefusal::MissingId),
        [one] => Ok(one.as_str()),
        _ => Err(IdentityRefusal::RepeatedId),
    }
}


/// The agent id of `<tenant>:<agent>:<sequence>:<index>`, whose tenant must equal the subject's; any other form is refused by name.
pub fn agent_from_ids<'a>(message_ids: &'a [String], tenant: &str, max_agent_bytes: usize) -> Result<&'a str, IdentityRefusal> {
    let id = single_id(message_ids)?;
    let parts: Vec<&str> = id.split(ID_SEPARATOR).take(MESSAGE_ID_PARTS + 1).collect();
    match parts.as_slice() {
        [id_tenant, agent, sequence, index] => {
            if *id_tenant != tenant {
                Err(IdentityRefusal::WrongTenant)
            } else if !is_agent_id(agent, max_agent_bytes) {
                Err(IdentityRefusal::BadAgent)
            } else if !is_canonical::<u64>(sequence) {
                Err(IdentityRefusal::BadSequence)
            } else if !is_canonical::<usize>(index) {
                Err(IdentityRefusal::BadIndex)
            } else {
                Ok(agent)
            }
        }
        _ => Err(IdentityRefusal::WrongPartCount),
    }
}


/// The stream's stored time stands for the receive time, so every redelivery of a message carries the same one.
pub fn stored_time(stored_nanos: Option<u64>) -> Result<u64, IdentityRefusal> {
    stored_nanos.ok_or(IdentityRefusal::NoStoredTime)
}
