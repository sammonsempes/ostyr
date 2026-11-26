//! The reload signals and the reload sources of the service: registered before any read, stopped and joined before the final drain.

use crate::service::LiveSettings;
use crate::types::{ReloadSignals, Stopper};
#[cfg(unix)]
use core_config::reload::reload;
use core_config::reload::ReloadEngine;
#[cfg(unix)]
use signal_hook::consts::SIGHUP;
#[cfg(unix)]
use signal_hook::iterator::Signals;
use std::io;
#[cfg(unix)]
use std::os::raw::c_int;
use std::sync::Arc;
#[cfg(unix)]
use std::thread::spawn;
use tracing::debug;


/// Called first in `main`: a `SIGHUP` during the start queues here and is handled once the reload thread runs.
#[cfg(unix)]
pub fn early_reload_signals() -> io::Result<ReloadSignals> {
    Signals::new([SIGHUP])
}


#[cfg(not(unix))]
pub fn early_reload_signals() -> io::Result<ReloadSignals> {
    Ok(ReloadSignals)
}


/// A stream that listens to no signal, for callers that drive the service in-process.
#[cfg(unix)]
pub fn quiet_reload_signals() -> io::Result<ReloadSignals> {
    Signals::new(Vec::<c_int>::new())
}


#[cfg(not(unix))]
pub fn quiet_reload_signals() -> io::Result<ReloadSignals> {
    Ok(ReloadSignals)
}


/// One reload per received signal; the stopper closes the stream and waits until the thread (and any reload it runs) is over.
#[cfg(unix)]
pub fn reload_on_signals(mut signals: ReloadSignals, engine: Arc<ReloadEngine<LiveSettings>>) -> Stopper {
    let handle = signals.handle();
    let thread = spawn(move || {
        signals.forever().for_each(|signal| {
            let outcome = reload(&engine);
            debug!(signal, ?outcome, "reload after signal");
        });
    });
    Box::new(move || {
        handle.close();
        let joined = thread.join().is_ok();
        debug!(joined, "signal thread stopped");
    })
}


#[cfg(not(unix))]
pub fn reload_on_signals(_signals: ReloadSignals, _engine: Arc<ReloadEngine<LiveSettings>>) -> Stopper {
    Box::new(|| debug!("no signal thread"))
}


/// The reload sources of a running service, stopped together.
#[derive(Default)]
pub struct Reloaders {
    pub stoppers: Vec<Stopper>,
}


/// Returns when every source has ended, so no reload starts or finishes after it.
pub fn stop_reloaders(reloaders: Reloaders) {
    reloaders.stoppers.into_iter().for_each(|stop| stop());
}
