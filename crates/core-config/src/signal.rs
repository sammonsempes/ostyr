use crate::reload::{reload, ReloadEngine};
use signal_hook::iterator::{Handle, Signals};
use std::io;
use std::os::raw::c_int;
use std::sync::Arc;
use std::thread;
use tracing::debug;


/// Dropping the guard closes the signal stream, which ends the thread.
pub struct SignalGuard {
    pub handle: Handle,
}


impl Drop for SignalGuard {
    fn drop(&mut self) {
        self.handle.close();
    }
}


/// Reloads once per received signal (`SIGHUP` in practice).
pub fn reload_on_signals<Config: Send + Sync + 'static>(engine: Arc<ReloadEngine<Config>>, signals: &[c_int]) -> io::Result<SignalGuard> {
    let mut stream = Signals::new(signals)?;
    let handle = stream.handle();
    thread::spawn(move || {
        stream.forever().for_each(|signal| {
            let outcome = reload(&engine);
            debug!(signal, ?outcome, "reload after signal");
        });
    });
    Ok(SignalGuard { handle })
}
