use crate::cursor::{open_state_dir, read_cursor};
use crate::error::SourceError;
use crate::follow::poll;
use crate::model::{Cursor, Follower, Paths, Report, SourceSettings, StateDir, Totals};
use crate::types::SharedSource;
use agent_channel::types::PauseFn;
use std::path::PathBuf;
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
    state: Arc<StateDir>,
    paths: Paths,
    settings: Arc<SourceSettings>,
    line_limit: usize,
) -> Result<(Follower, Result<Report, SourceError>), SourceError> {
    let joined = tokio::task::spawn_blocking(move || {
        let outcome = poll(&mut follower, &state, &paths, &settings, line_limit);
        (follower, outcome)
    })
    .await?;
    Ok(joined)
}


/// The start checks and the cursor read, on the blocking pool: a hostile state directory must not stall the async tasks.
pub async fn load_cursor_blocking(cursor_file: PathBuf) -> Result<(StateDir, Cursor), SourceError> {
    tokio::task::spawn_blocking(move || {
        let state = open_state_dir(&cursor_file)?;
        let cursor = read_cursor(&state, &cursor_file)?;
        Ok((state, cursor))
    })
    .await?
}


/// Polls `max_polls` times, reading the settings snapshot afresh each time so a reload applies to the next poll; `pause` is injected.
pub async fn run_source(shared: &SharedSource, paths: &Paths, line_limit: usize, max_polls: u64, pause: &PauseFn) -> Result<Totals, SourceError> {
    let (opened, cursor) = load_cursor_blocking(paths.cursor_file.clone()).await?;
    let state = Arc::new(opened);
    let mut follower = Follower {
        cursor,
        ..Follower::default()
    };
    let mut totals = Totals::default();
    for _ in 0..max_polls {
        let settings = shared.load_full();
        let (moved, outcome) = poll_blocking(follower, Arc::clone(&state), paths.clone(), Arc::clone(&settings), line_limit).await?;
        follower = moved;
        totals = tally(totals, outcome);
        pause(Duration::from_millis(settings.poll_millis)).await;
    }
    Ok(totals)
}
