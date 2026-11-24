use crate::model::{Bounds, End, Halves, BUFFER_BYTES};
use crate::types::{BoxRead, BoxWrite};
use futures_util::stream;
use futures_util::{StreamExt, TryStreamExt};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio::time::{sleep, sleep_until, Instant};
use tokio_util::io::ReaderStream;


/// When the last write to either destination completed, in milliseconds since `start`.
#[derive(Debug)]
pub struct Progress {
    pub start: Instant,
    pub last_write: AtomicU64,
}


pub fn new_progress() -> Progress {
    Progress {
        start: Instant::now(),
        last_write: AtomicU64::new(0),
    }
}


pub fn elapsed_millis(progress: &Progress) -> u64 {
    u64::try_from(progress.start.elapsed().as_millis()).unwrap_or(u64::MAX)
}


pub fn touch(progress: &Progress) {
    progress.last_write.store(elapsed_millis(progress), Ordering::Relaxed);
}


/// One direction: fixed-size reads, each written out before the next read; the write side is shut down at EOF.
pub async fn pump(reader: BoxRead, writer: BoxWrite, progress: Arc<Progress>) -> io::Result<()> {
    let mut finished = ReaderStream::with_capacity(reader, BUFFER_BYTES)
        .try_fold(writer, |mut destination, chunk| {
            let written = Arc::clone(&progress);
            async move {
                destination.write_all(&chunk).await?;
                touch(&written);
                Ok(destination)
            }
        })
        .await?;
    finished.shutdown().await
}


/// Completes when a whole `idle` passed with no write completing in either direction.
pub async fn idle_expired(progress: Arc<Progress>, idle: Duration) -> Option<bool> {
    Box::pin(stream::unfold((), |()| {
        let watched = Arc::clone(&progress);
        async move {
            let before = watched.last_write.load(Ordering::Relaxed);
            sleep_until(watched.start + Duration::from_millis(before) + idle).await;
            Some((watched.last_write.load(Ordering::Relaxed) == before, ()))
        }
    }))
    .filter(|expired| std::future::ready(*expired))
    .next()
    .await
}


pub async fn both_directions(client: Halves, upstream: Halves, progress: Arc<Progress>) -> io::Result<()> {
    tokio::try_join!(
        pump(client.read, upstream.write, Arc::clone(&progress)),
        pump(upstream.read, client.write, progress)
    )?;
    Ok(())
}


/// Ends at both EOFs, an error, idle, lifetime or the cut; dropping the halves closes both sockets.
pub async fn relay_halves(client: Halves, upstream: Halves, bounds: &Bounds, mut cut: watch::Receiver<bool>) -> End {
    let progress = Arc::new(new_progress());
    tokio::select! {
        result = both_directions(client, upstream, Arc::clone(&progress)) => if result.is_ok() { End::Completed } else { End::CopyError },
        _ = idle_expired(progress, bounds.idle) => End::Idle,
        () = sleep(bounds.lifetime) => End::Lifetime,
        _ = cut.wait_for(|stop| *stop) => End::Cut,
    }
}
