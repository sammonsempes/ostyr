//! `SIGHUP` reloads the settings on its own thread; dropping the guard closes the stream and joins the thread, so a reload in flight ends first.

use crate::model::Live;
use core_config::reload::ReloadEngine;
use std::sync::Arc;


#[cfg(unix)]
pub struct Hangup {
    pub stream: signal_hook::iterator::Signals,
}


#[cfg(unix)]
pub struct HangupThread {
    pub handle: signal_hook::iterator::Handle,
    pub worker: Option<std::thread::JoinHandle<()>>,
}


/// Registered before the first round, so a `SIGHUP` at any later moment is queued, never fatal.
#[cfg(unix)]
pub fn arm_hangup() -> std::io::Result<Hangup> {
    signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP]).map(|stream| Hangup { stream })
}


#[cfg(unix)]
pub fn follow_hangup(hangup: Hangup, engine: Arc<ReloadEngine<Live>>) -> HangupThread {
    let mut stream = hangup.stream;
    let handle = stream.handle();
    let worker = std::thread::spawn(move || {
        stream.forever().for_each(|_signal| {
            let outcome = core_config::reload::reload(&engine);
            tracing::info!(?outcome, "reload after SIGHUP");
        });
    });
    HangupThread {
        handle,
        worker: Some(worker),
    }
}


#[cfg(unix)]
impl Drop for HangupThread {
    fn drop(&mut self) {
        self.handle.close();
        self.worker.take().into_iter().for_each(|worker| {
            if worker.join().is_err() {
                tracing::error!("the reload thread panicked");
            }
        });
    }
}


#[cfg(not(unix))]
pub struct Hangup;


#[cfg(not(unix))]
pub struct HangupThread;


#[cfg(not(unix))]
pub fn arm_hangup() -> std::io::Result<Hangup> {
    Ok(Hangup)
}


#[cfg(not(unix))]
pub fn follow_hangup(_hangup: Hangup, _engine: Arc<ReloadEngine<Live>>) -> HangupThread {
    HangupThread
}
