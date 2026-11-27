use crate::reload::{reload, ReloadEngine};
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::{Handle, Signals};
use std::io;
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing::{debug, info, warn};


const DROP_JOIN_POLLS: usize = 100;


const DROP_JOIN_INTERVAL: Duration = Duration::from_millis(10);


/// The reload thread's stop switch: `stop_signals` joins it unbounded, dropping the guard joins it for a bounded time and logs a timeout.
pub struct SignalGuard {
    pub handle: Handle,
    pub thread: Option<JoinHandle<()>>,
    pub in_flight: Arc<AtomicBool>,
}


/// The SIGHUP stream a service registers synchronously before any read, queued until the engine exists.
pub struct EarlySignals {
    pub reload: Signals,
}


impl Drop for SignalGuard {
    fn drop(&mut self) {
        let joined = close_and_join(self, DROP_JOIN_POLLS, DROP_JOIN_INTERVAL);
        if !joined {
            warn!("signal thread still running after the drop bound");
        }
    }
}


/// Closes the stream and joins the reload thread for at most `max_polls` intervals, as `Drop` does with its constants; true when it ended cleanly.
pub fn close_and_join(guard: &mut SignalGuard, max_polls: usize, interval: Duration) -> bool {
    guard.handle.close();
    guard.thread.take().is_none_or(|thread| join_bounded(thread, max_polls, interval))
}


/// True while the reload thread is inside a reload.
pub fn reload_in_flight(guard: &SignalGuard) -> bool {
    guard.in_flight.load(Ordering::SeqCst)
}


/// Waits for the thread at most `max_polls` intervals; true when it ended cleanly.
pub fn join_bounded(thread: JoinHandle<()>, max_polls: usize, interval: Duration) -> bool {
    let finished = (0..max_polls).any(|_| {
        thread.is_finished() || {
            thread::sleep(interval);
            false
        }
    }) || thread.is_finished();
    finished && thread.join().is_ok()
}


/// Closes the stream and waits until the reload thread, and any reload it runs, is over; true when it ended cleanly.
pub fn stop_signals(mut guard: SignalGuard) -> bool {
    guard.handle.close();
    let in_flight = reload_in_flight(&guard);
    info!(in_flight, "stopping the reload thread, a reload in flight finishes first");
    let joined = guard.thread.take().is_none_or(|thread| thread.join().is_ok());
    debug!(joined, "signal thread stopped");
    joined
}


/// Registers SIGHUP now (SIGINT and SIGTERM keep their default action until a service arms them): call it first in `main`, before any file read.
pub fn early_signals() -> io::Result<EarlySignals> {
    Ok(EarlySignals {
        reload: Signals::new([SIGHUP])?,
    })
}


/// Handles the signals queued since `early_signals` and the later ones: at most one reload per pending signal (signal-hook collapses repeats).
pub fn reload_on_stream<Config: Send + Sync + 'static>(mut stream: Signals, engine: Arc<ReloadEngine<Config>>) -> SignalGuard {
    let handle = stream.handle();
    let in_flight = Arc::new(AtomicBool::new(false));
    let in_flight_in_thread = Arc::clone(&in_flight);
    let thread = thread::spawn(move || {
        stream.forever().for_each(|signal| {
            in_flight_in_thread.store(true, Ordering::SeqCst);
            let outcome = reload(&engine);
            in_flight_in_thread.store(false, Ordering::SeqCst);
            debug!(signal, ?outcome, "reload after signal");
        });
    });
    SignalGuard {
        handle,
        thread: Some(thread),
        in_flight,
    }
}


/// Reloads once per received signal (`SIGHUP` in practice).
pub fn reload_on_signals<Config: Send + Sync + 'static>(engine: Arc<ReloadEngine<Config>>, signals: &[c_int]) -> io::Result<SignalGuard> {
    Signals::new(signals).map(|stream| reload_on_stream(stream, engine))
}
