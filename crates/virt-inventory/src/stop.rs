//! `SIGTERM` and `SIGINT` are also read on a thread of their own, so a signal that arrives while a round blocks is logged by name when it comes.

use tracing::{info, warn};


pub const SIGNAL_TERMINATE: i32 = 15;


pub const SIGNAL_INTERRUPT: i32 = 2;


pub const OTHER_SIGNAL: &str = "an unexpected signal";


pub fn signal_name(signal: i32) -> &'static str {
    match signal {
        SIGNAL_TERMINATE => "SIGTERM",
        SIGNAL_INTERRUPT => "SIGINT",
        _ => OTHER_SIGNAL,
    }
}


/// The first signal asks for the stop, every later one is named and ignored: the round in flight always finishes; answers how many were seen.
pub fn note_signals(signals: impl Iterator<Item = i32>) -> usize {
    signals.fold(0, |seen, signal| {
        let name = signal_name(signal);
        if seen == 0 {
            info!(name, "stop requested, the round in flight finishes first");
        } else {
            warn!(name, "a further interrupt is ignored, the round in flight finishes first");
        }
        seen + 1
    })
}


/// A stop thread that panicked is named; answers whether it ended well.
pub fn joined(outcome: std::thread::Result<usize>) -> bool {
    let ended_well = outcome.is_ok();
    if !ended_well {
        tracing::error!("the stop thread panicked");
    }
    ended_well
}


#[cfg(unix)]
pub struct Stops {
    pub stream: signal_hook::iterator::Signals,
}


#[cfg(unix)]
pub struct StopsThread {
    pub handle: signal_hook::iterator::Handle,
    pub worker: Option<std::thread::JoinHandle<usize>>,
}


/// Registered next to tokio's own handlers, before the first round.
#[cfg(unix)]
pub fn arm_stops() -> std::io::Result<Stops> {
    signal_hook::iterator::Signals::new([SIGNAL_TERMINATE, SIGNAL_INTERRUPT]).map(|stream| Stops { stream })
}


#[cfg(unix)]
pub fn follow_stops(stops: Stops) -> StopsThread {
    let mut stream = stops.stream;
    let handle = stream.handle();
    let worker = std::thread::spawn(move || note_signals(stream.forever()));
    StopsThread {
        handle,
        worker: Some(worker),
    }
}


#[cfg(unix)]
impl Drop for StopsThread {
    fn drop(&mut self) {
        self.handle.close();
        self.worker.take().into_iter().for_each(|worker| {
            joined(worker.join());
        });
    }
}


#[cfg(not(unix))]
pub struct Stops;


#[cfg(not(unix))]
pub struct StopsThread;


#[cfg(not(unix))]
pub fn arm_stops() -> std::io::Result<Stops> {
    Ok(Stops)
}


#[cfg(not(unix))]
pub fn follow_stops(_stops: Stops) -> StopsThread {
    StopsThread
}
