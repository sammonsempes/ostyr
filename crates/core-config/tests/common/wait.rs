use std::thread;
use std::time::Duration;


pub const MAX_POLLS: usize = 100;


pub const POLL_INTERVAL: Duration = Duration::from_millis(50);


pub fn wait_until(condition: impl Fn() -> bool) -> bool {
    (0..MAX_POLLS).any(|_| {
        condition() || {
            thread::sleep(POLL_INTERVAL);
            false
        }
    })
}
