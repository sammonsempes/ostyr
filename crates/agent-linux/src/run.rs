use crate::cursor::{check_state_dir, read_cursor};
use crate::error::SourceError;
use crate::follow::poll;
use crate::model::{Follower, Paths, Report, SourceSettings, Totals};
use crate::types::SharedSource;
use agent_channel::types::PauseFn;
use std::sync::Arc;
use std::time::Duration;


/// Adds one poll to the totals; a failed poll is logged and counted, the next poll tries again, and a missing export file is logged once per absence.
pub fn tally(totals: Totals, outcome: Result<Report, SourceError>) -> Totals {
    match outcome {
        Ok(report) => {
            if report.missing && !totals.waiting {
                tracing::warn!("export file not found, waiting for it");
            }
            Totals {
                polls: totals.polls + 1,
                spooled: totals.spooled + report.spooled,
                malformed: totals.malformed + report.malformed,
                unknown: totals.unknown + report.unknown,
                oversized: totals.oversized + report.oversized,
                rotations: totals.rotations + u64::from(report.rotated),
                waiting: report.missing,
                ..totals
            }
        }
        Err(error) => {
            tracing::warn!(%error, "export poll failed");
            Totals {
                polls: totals.polls + 1,
                failures: totals.failures + 1,
                ..totals
            }
        }
    }
}


/// One poll on the blocking pool, so file reads never stall the async tasks (the agent keepalive); the follower goes in and comes back.
pub async fn poll_blocking(
    mut follower: Follower,
    paths: Paths,
    settings: Arc<SourceSettings>,
    line_limit: usize,
) -> Result<(Follower, Result<Report, SourceError>), SourceError> {
    let joined = tokio::task::spawn_blocking(move || {
        let outcome = poll(&mut follower, &paths, &settings, line_limit);
        (follower, outcome)
    })
    .await?;
    Ok(joined)
}


/// Polls `max_polls` times, reading the settings snapshot afresh each time so a reload applies to the next poll; `pause` is injected.
pub async fn run_source(shared: &SharedSource, paths: &Paths, line_limit: usize, max_polls: u64, pause: &PauseFn) -> Result<Totals, SourceError> {
    check_state_dir(&paths.cursor_file)?;
    let cursor = read_cursor(&paths.cursor_file)?;
    let mut follower = Follower { cursor, current: None };
    let mut totals = Totals::default();
    for _ in 0..max_polls {
        let settings = shared.load_full();
        let (moved, outcome) = poll_blocking(follower, paths.clone(), Arc::clone(&settings), line_limit).await?;
        follower = moved;
        totals = tally(totals, outcome);
        pause(Duration::from_millis(settings.poll_millis)).await;
    }
    Ok(totals)
}
