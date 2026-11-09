use crate::error::{ExportError, PermanentRejection};
use crate::types::{BoxError, PostFn, SleepFn};
use std::ops::ControlFlow;
use std::time::Duration;


pub const BACKOFF_BASE: Duration = Duration::from_millis(200);


pub const BACKOFF_CAP: Duration = Duration::from_secs(30);


pub const MAX_ATTEMPTS: u32 = 8;


pub const BACKOFF_FACTOR: u32 = 2;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub base: Duration,
    pub cap: Duration,
    pub max_attempts: u32,
}


impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base: BACKOFF_BASE,
            cap: BACKOFF_CAP,
            max_attempts: MAX_ATTEMPTS,
        }
    }
}


/// `base * 2^attempt`, never above `cap`, never overflowing.
pub fn backoff_delay(policy: &RetryPolicy, attempt: u32) -> Duration {
    policy.base.saturating_mul(BACKOFF_FACTOR.saturating_pow(attempt)).min(policy.cap)
}


/// A JSON array of already serialised events.
pub fn batch_body(events: &[String]) -> String {
    format!("[{}]", events.join(","))
}


/// Chunks of at most `batch_size` events (at least one), each with its event count and JSON array body.
pub fn batches(events: &[String], batch_size: usize) -> Vec<(usize, String)> {
    events.chunks(batch_size.max(1)).map(|chunk| (chunk.len(), batch_body(chunk))).collect()
}


/// Posts `body` up to `policy.max_attempts` times, sleeping `backoff_delay` between attempts; returns the attempts used. A `PermanentRejection` stops at once.
pub fn deliver(policy: &RetryPolicy, post: &mut PostFn, sleep: &mut SleepFn, body: &str) -> Result<u32, ExportError> {
    let outcome = (0..policy.max_attempts).try_fold(None::<BoxError>, |_previous, attempt| match post(body) {
        Ok(()) => ControlFlow::Break(Ok(attempt + 1)),
        Err(error) => match error.downcast_ref::<PermanentRejection>() {
            Some(rejection) => {
                tracing::warn!(status = rejection.status, "export target rejected the batch permanently");
                ControlFlow::Break(Err(ExportError::Rejected { status: rejection.status }))
            }
            None => {
                tracing::warn!(attempt, %error, "webhook post failed");
                if attempt + 1 < policy.max_attempts {
                    sleep(backoff_delay(policy, attempt));
                }
                ControlFlow::Continue(Some(error))
            }
        },
    });
    match outcome {
        ControlFlow::Break(result) => result,
        ControlFlow::Continue(last_error) => Err(ExportError::Exhausted {
            attempts: policy.max_attempts,
            source: last_error,
        }),
    }
}
