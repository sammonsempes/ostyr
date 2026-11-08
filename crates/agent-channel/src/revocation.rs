use crate::error::RevocationError;
use crate::model::{RawRevocationFile, Revocations};
use crate::types::{RevocationSender, RevocationWatch};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;


pub const REVOCATION_SECTION: &str = "revoked_serials";


/// Lowercase, no leading zero: the form a serial takes in the list and when read from a certificate.
pub fn canonical_serial(hexadecimal: &str) -> String {
    hexadecimal.to_ascii_lowercase().trim_start_matches('0').to_owned()
}


/// Accepts the `openssl` notation with colons; refuses anything that is not hexadecimal or is zero.
pub fn parse_serial(text: &str) -> Result<String, RevocationError> {
    let digits: String = text.trim().chars().filter(|character| *character != ':').collect();
    if digits.is_empty() || !digits.chars().all(|character| character.is_ascii_hexdigit()) {
        Err(RevocationError::NotHexadecimal(text.to_owned()))
    } else {
        Some(canonical_serial(&digits))
            .filter(|serial| !serial.is_empty())
            .ok_or_else(|| RevocationError::Zero(text.to_owned()))
    }
}


impl TryFrom<RawRevocationFile> for Revocations {
    type Error = RevocationError;

    fn try_from(file: RawRevocationFile) -> Result<Self, Self::Error> {
        let serials = file
            .revoked_serials
            .iter()
            .map(|text| parse_serial(text))
            .collect::<Result<BTreeSet<String>, RevocationError>>()?;
        Ok(Revocations { serials })
    }
}


pub fn is_revoked(revocations: &Revocations, serial: &str) -> bool {
    revocations.serials.contains(serial)
}


/// The serials of `chain` that are on the list.
pub fn revoked_in(revocations: &Revocations, chain: &[String]) -> Vec<String> {
    chain.iter().filter(|serial| is_revoked(revocations, serial)).cloned().collect()
}


pub fn revoked_now(watcher: &RevocationWatch, chain: &[String]) -> Vec<String> {
    revoked_in(&watcher.borrow(), chain)
}


/// One line per serial so a reload's diff and audit entry show which serial was added or removed.
pub fn revocations_state(revocations: &Revocations) -> ConfigState {
    revocations
        .serials
        .iter()
        .map(|serial| (format!("{REVOCATION_SECTION}.{serial}"), "revoked".to_owned()))
        .collect()
}


pub fn revocations_loader(path: PathBuf) -> Box<LoaderFn<Revocations>> {
    Box::new(move || load_file::<Revocations>(&path))
}


/// Forwards every applied list to the connections through `sender`.
pub fn publish_subscriber(sender: RevocationSender) -> Subscriber<Revocations> {
    Subscriber {
        section: REVOCATION_SECTION.to_owned(),
        validate: Box::new(|_candidate| Ok(())),
        apply: Box::new(move |applied| {
            sender.send_replace(applied.clone());
        }),
    }
}


/// The engine owns the sender: dropping it closes every connection (fail closed). The first load must succeed.
pub fn open_revocation_engine(
    path: PathBuf,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<(ReloadEngine<Revocations>, RevocationWatch), ConfigError> {
    let sender: RevocationSender = Arc::new(watch::channel(Revocations::default()).0);
    let engine = open_engine(
        revocations_loader(path),
        revocations_state,
        vec![publish_subscriber(Arc::clone(&sender))],
        audit,
        context,
    )?;
    sender.send_replace(current_config(&engine).as_ref().clone());
    Ok((engine, sender.subscribe()))
}
