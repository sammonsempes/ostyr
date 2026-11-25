#![cfg(unix)]
use metrics_ingest::serve::{directives_of, install_logging, warn_unreadable_directives, ServeError};
use std::env::VarError;
use std::error::Error;
use std::ffi::OsString;


#[test]
fn a_second_subscriber_is_refused_and_the_first_is_installed() -> Result<(), Box<dyn Error>> {
    install_logging(Some("info"))?;
    let refused = install_logging(None).err().ok_or("a second subscriber was accepted")?;
    assert!(matches!(refused, ServeError::Subscriber(_)));
    assert_eq!(refused.to_string(), "a log subscriber is already installed");
    Ok(())
}


#[test]
fn only_a_readable_rust_log_gives_directives_and_only_non_unicode_warns() -> Result<(), Box<dyn Error>> {
    let present: Result<String, VarError> = Ok("info".to_owned());
    let absent: Result<String, VarError> = Err(VarError::NotPresent);
    let garbled: Result<String, VarError> = Err(VarError::NotUnicode(OsString::from("x")));
    assert_eq!(directives_of(&present), Some("info"));
    assert_eq!(directives_of(&absent), None);
    assert_eq!(directives_of(&garbled), None);
    [&present, &absent, &garbled]
        .iter()
        .for_each(|variable| warn_unreadable_directives(variable));
    Ok(())
}
