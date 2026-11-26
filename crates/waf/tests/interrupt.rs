#![cfg(target_os = "linux")]

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::low_level::raise;
use std::error::Error;
use std::time::Duration;
use waf::serve::signal_source;


const HANG_GUARD: Duration = Duration::from_secs(120);


#[test]
fn the_signal_source_queues_hangup_and_both_stop_signals() -> Result<(), Box<dyn Error>> {
    let receiver = signal_source()?;
    raise(SIGHUP)?;
    assert_eq!(receiver.recv_timeout(HANG_GUARD)?, SIGHUP);
    raise(SIGTERM)?;
    assert_eq!(receiver.recv_timeout(HANG_GUARD)?, SIGTERM);
    raise(SIGINT)?;
    assert_eq!(receiver.recv_timeout(HANG_GUARD)?, SIGINT);
    drop(receiver);
    raise(SIGHUP)?;
    Ok(())
}
