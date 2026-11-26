//! Usage: `follow_eve <eve.json> <state_dir> <ticks> <tick_millis>`: follows the file, saves the cursor after each tick, prints the totals.


#[cfg(unix)]
use ndr::follow::{cursor_of, follow_tick, load_state, open_state_dir, resume, store_state};
#[cfg(unix)]
use ndr::model::Limits;
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::io::{stdout, Write};
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;


#[cfg(unix)]
fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let usage = "usage: follow_eve <eve.json> <state_dir> <ticks> <tick_millis>";
    let mut args = std::env::args().skip(1);
    let eve = PathBuf::from(args.next().ok_or(usage)?);
    let state_dir = open_state_dir(&PathBuf::from(args.next().ok_or(usage)?))?;
    let ticks: usize = args.next().ok_or(usage)?.parse()?;
    let pause = Duration::from_millis(args.next().ok_or(usage)?.parse()?);
    let limits = Limits::default();
    let saved = load_state(&state_dir, "eve.state")?;
    let (mut follower, start) = resume(&eve, saved.as_ref(), &limits)?;
    let mut total_lines = usize::default();
    let mut malformed = start.malformed;
    let mut truncated = start.eve_truncated;
    let mut rotations = u64::default();
    let mut unread = u64::default();
    let mut skipping = u64::default();
    for _ in 0..ticks {
        let ticked = follow_tick(&eve, &follower, &limits)?;
        total_lines += ticked.lines.len();
        malformed += ticked.counts.malformed;
        truncated += ticked.counts.eve_truncated;
        rotations += ticked.counts.rotations;
        unread += ticked.counts.rotated_unread_bytes;
        skipping = ticked.skipping_bytes;
        follower = ticked.follower;
        store_state(&state_dir, "eve.state.tmp", "eve.state", &cursor_of(&follower)?)?;
        std::thread::sleep(pause);
    }
    writeln!(
        stdout(),
        "lines={total_lines} malformed={malformed} eve_truncated={truncated} rotations={rotations} rotated_unread_bytes={unread} skipping_bytes={skipping}"
    )?;
    Ok(())
}


#[cfg(not(unix))]
fn main() {}
