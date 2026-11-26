#![cfg(target_os = "linux")]

use std::error::Error;
use waf::error::ServeError;
use waf::serve::{install_logging, run};


#[test]
fn logging_installs_once_and_a_second_run_reports_it() -> Result<(), Box<dyn Error>> {
    let arguments = vec!["/nonexistent/settings.yaml".to_owned()];
    let first = run(&arguments).err().ok_or("started")?;
    assert!(matches!(first, ServeError::Settings(_)));
    let second = run(&arguments).err().ok_or("started")?;
    assert!(matches!(second, ServeError::Logging(_)));
    assert!(install_logging().is_err());
    assert!(matches!(run(&[]), Err(ServeError::Logging(_))));
    Ok(())
}
