use crate::support::{halves, link, TestResult};
use relay::copy::{elapsed_millis, new_progress, relay_halves, touch};
use relay::model::{Bounds, End, DEFAULT_IDLE_SECONDS, DEFAULT_MAX_LIFETIME_SECONDS};
use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::{advance, sleep, Instant};


const BOUNDS: Bounds = Bounds {
    connect: Duration::from_secs(5),
    idle: Duration::from_secs(DEFAULT_IDLE_SECONDS),
    lifetime: Duration::from_secs(DEFAULT_MAX_LIFETIME_SECONDS),
};


const TRICKLE_SECONDS: u64 = 100;


const TRICKLE_WRITES: usize = 60;


const FIRST_BYTES_AT: u64 = 100;


const BIG_WRITE: usize = 1000;


#[tokio::test(start_paused = true)]
async fn bytes_pass_both_ways_and_both_sides_close() -> TestResult {
    let (client, mut client_end) = link();
    let (upstream, mut upstream_end) = link();
    let (_stop, cut) = watch::channel(false);
    let relay = tokio::spawn(async move { relay_halves(client, upstream, &BOUNDS, cut).await });
    client_end.write_all(b"ping").await?;
    client_end.shutdown().await?;
    let mut received = Vec::new();
    upstream_end.read_to_end(&mut received).await?;
    assert_eq!(received, b"ping");
    upstream_end.write_all(b"pong").await?;
    upstream_end.shutdown().await?;
    let mut answer = Vec::new();
    client_end.read_to_end(&mut answer).await?;
    assert_eq!(answer, b"pong");
    assert_eq!(relay.await?, End::Completed);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_half_close_lets_the_other_direction_finish() -> TestResult {
    let (client, mut client_end) = link();
    let (upstream, mut upstream_end) = link();
    let (_stop, cut) = watch::channel(false);
    let relay = tokio::spawn(async move { relay_halves(client, upstream, &BOUNDS, cut).await });
    client_end.shutdown().await?;
    let mut nothing = Vec::new();
    upstream_end.read_to_end(&mut nothing).await?;
    assert!(nothing.is_empty());
    sleep(Duration::from_secs(TRICKLE_SECONDS)).await;
    upstream_end.write_all(b"late").await?;
    upstream_end.shutdown().await?;
    let mut late = Vec::new();
    client_end.read_to_end(&mut late).await?;
    assert_eq!(late, b"late");
    assert_eq!(relay.await?, End::Completed);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_half_closed_direction_keeps_its_own_idle_bound() -> TestResult {
    let (client, mut client_end) = link();
    let (upstream, _upstream_end) = link();
    let (_stop, cut) = watch::channel(false);
    let started = Instant::now();
    client_end.shutdown().await?;
    let end = relay_halves(client, upstream, &BOUNDS, cut).await;
    assert_eq!(end, End::Idle);
    assert_eq!(started.elapsed(), BOUNDS.idle);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn an_error_on_one_side_ends_both_directions() -> TestResult {
    let (client, client_end) = link();
    let (upstream, mut upstream_end) = link();
    let (_stop, cut) = watch::channel(false);
    let relay = tokio::spawn(async move { relay_halves(client, upstream, &BOUNDS, cut).await });
    drop(client_end);
    upstream_end.write_all(b"into the void").await?;
    assert_eq!(relay.await?, End::CopyError);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn silence_ends_at_idle() -> TestResult {
    let (client, _client_end) = link();
    let (upstream, _upstream_end) = link();
    let (_stop, cut) = watch::channel(false);
    let started = Instant::now();
    assert_eq!(relay_halves(client, upstream, &BOUNDS, cut).await, End::Idle);
    assert_eq!(started.elapsed(), BOUNDS.idle);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_slow_trickle_ends_at_the_lifetime() -> TestResult {
    let (client, mut client_end) = link();
    let (upstream, mut upstream_end) = link();
    let (_stop, cut) = watch::channel(false);
    let writer = tokio::spawn(async move {
        let mut written = Ok(());
        for _round in 0..TRICKLE_WRITES {
            written = client_end.write_all(b"x").await;
            sleep(Duration::from_secs(TRICKLE_SECONDS)).await;
        }
        written
    });
    let drain = tokio::spawn(async move {
        let mut sink = Vec::new();
        upstream_end.read_to_end(&mut sink).await
    });
    let started = Instant::now();
    assert_eq!(relay_halves(client, upstream, &BOUNDS, cut).await, End::Lifetime);
    assert_eq!(started.elapsed(), BOUNDS.lifetime);
    writer.abort();
    drain.abort();
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn reads_alone_never_restart_the_idle_clock() -> TestResult {
    let (client, mut client_end) = link();
    let (small, _small_end) = duplex(1);
    let upstream = halves(small);
    let (_stop, cut) = watch::channel(false);
    let writer = tokio::spawn(async move {
        sleep(Duration::from_secs(FIRST_BYTES_AT)).await;
        client_end.write_all(&[0; BIG_WRITE]).await
    });
    let started = Instant::now();
    assert_eq!(relay_halves(client, upstream, &BOUNDS, cut).await, End::Idle);
    assert_eq!(started.elapsed(), BOUNDS.idle);
    writer.abort();
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_cut_ends_the_connection() -> TestResult {
    let (client, _client_end) = link();
    let (upstream, _upstream_end) = link();
    let (stop, cut) = watch::channel(false);
    let relay = tokio::spawn(async move { relay_halves(client, upstream, &BOUNDS, cut).await });
    stop.send_replace(true);
    assert_eq!(relay.await?, End::Cut);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn progress_counts_milliseconds_since_the_start() -> TestResult {
    let progress = new_progress();
    assert_eq!(elapsed_millis(&progress), 0);
    advance(Duration::from_secs(1)).await;
    touch(&progress);
    assert_eq!(progress.last_write.load(std::sync::atomic::Ordering::Relaxed), elapsed_millis(&progress));
    Ok(())
}
