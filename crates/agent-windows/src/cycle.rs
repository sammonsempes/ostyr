use crate::error::PollError;
use crate::model::{Channel, ChannelState, PollEnv, PollTotals, MAX_REPOLLS_PER_CYCLE, POLL_INTERVAL_SECONDS};
use crate::poll::poll_channel;
use std::thread::sleep;
use std::time::Duration;


pub fn sleep_seconds(seconds: u64) {
    sleep(Duration::from_secs(seconds));
}


pub fn poll_cycle(
    env: &mut PollEnv<'_>,
    channel: &Channel,
    state: &mut ChannelState,
    wait: &mut dyn FnMut(u64),
) -> Result<Vec<PollTotals>, PollError> {
    let first = poll_channel(env, channel, state)?;
    let polls = (0..MAX_REPOLLS_PER_CYCLE).try_fold(vec![first], |mut done, _| {
        let again = done.last().is_some_and(|last| last.full_batches > 0);
        if again {
            done.push(poll_channel(env, channel, state)?);
        }
        Ok::<Vec<PollTotals>, PollError>(done)
    })?;
    wait(POLL_INTERVAL_SECONDS);
    Ok(polls)
}
