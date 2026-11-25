#![cfg(target_os = "linux")]

use signal_hook::consts::SIGTERM;
use signal_hook::iterator::Signals;
use signal_hook::low_level::raise;
use std::error::Error;
use std::thread::{sleep, spawn};
use std::time::Duration;
use waf::serve::wait_for_interrupt;


const ATTEMPTS: usize = 3_000;


const STEP: Duration = Duration::from_millis(10);


#[test]
fn the_interrupt_wait_returns_on_sigterm() -> Result<(), Box<dyn Error>> {
    let _absorb = Signals::new([SIGTERM])?;
    let waiter = spawn(wait_for_interrupt);
    (0..ATTEMPTS).try_for_each(|_| {
        let finished = waiter.is_finished();
        if finished {
            Ok(())
        } else {
            sleep(STEP);
            raise(SIGTERM)
        }
    })?;
    assert!(waiter.is_finished());
    waiter.join().map_err(|_| "waiter panicked")??;
    Ok(())
}
