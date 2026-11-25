#![cfg(unix)]
use metrics_ingest::serve::{install_logging, ServeError};
use std::error::Error;


#[test]
fn a_second_subscriber_is_refused_and_the_first_is_installed() -> Result<(), Box<dyn Error>> {
    install_logging(Some("info"))?;
    let refused = install_logging(None).err().ok_or("a second subscriber was accepted")?;
    assert!(matches!(refused, ServeError::Subscriber(_)));
    assert_eq!(refused.to_string(), "a log subscriber is already installed");
    Ok(())
}
