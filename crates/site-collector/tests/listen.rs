#[path = "support/types.rs"]
mod types;


use core_audit::log::{append, open_file_log};
use core_config::reload::{open_engine, reload, ReloadContext, ReloadEngine, ReloadOutcome};
use site_collector::admission::{collector_config, source_counters, tracked_sources, untracked_dropped};
use site_collector::error::ListenError;
use site_collector::listen::{
    bump, count_reason, handle_datagram, listener_tenant, open_runtime, priority_of, prune_if_due, receive_cycle, run, sync_settings,
};
use site_collector::listen_model::{
    ListenerSettings, Runtime, SharedSocket, DEFAULT_BURST, DEFAULT_MAX_SOURCES, DEFAULT_RATE_PER_SECOND, DEFAULT_SOURCE_SHARE_PERCENT,
    MAX_TENANT_BYTES, PRUNE_INTERVAL_MS,
};
use site_collector::listen_settings::{
    bind_socket, collector_config_of, open_listener_engine, parse_listen, settings_loader, settings_state, source_key, validate_settings,
};
use site_collector::model::{DropReason, DEFAULT_UNKNOWN_SHARE_PERCENT, MAX_MESSAGE_BYTES, MAX_SHARE_PERCENT, MAX_UNKNOWN_SHARE_PERCENT};
use site_collector::spool::{open_spool, read_from, spool_stats};
use site_collector::spool_model::{Priority, SpoolConfig, MAX_FRAME_BYTES};
use std::fs;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tempfile::TempDir;
use types::TestResult;


const YEAR: i32 = 2003;


const LINE: &str = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - hello";


const LOW_LINE: &str = "<14>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - hello";


const TENANT_LINE: &str = "<34>1 2003-10-11T22:14:15.003Z host su - ID47 [tenant@1 id=\"other\"] hello";


const BIG_DATAGRAM: usize = 60_000;


const SOURCE_PORT: u16 = 5140;


const TEST_NET: u32 = 0xC000_0200;


const TWO: u64 = 2;


const THREE: u64 = 3;


const TWO_U8: u8 = 2;


const THREE_U8: u8 = 3;


const NEW_RATE: u64 = 7;


const SEGMENTS_IN_TOTAL: u64 = 3;


const FLOOD: usize = 10;


const TABLE: usize = 2;


fn source(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(TEST_NET + u32::from(last))), SOURCE_PORT)
}


fn settings() -> ListenerSettings {
    ListenerSettings {
        listen: "127.0.0.1:0".to_owned(),
        tenant: "acme".to_owned(),
        rate_per_second: DEFAULT_RATE_PER_SECOND,
        burst: DEFAULT_BURST,
        source_share_percent: DEFAULT_SOURCE_SHARE_PERCENT,
        unknown_share_percent: DEFAULT_UNKNOWN_SHARE_PERCENT,
        max_sources: DEFAULT_MAX_SOURCES,
        drop_unknown: false,
        sources: Vec::new(),
    }
}


fn runtime_in(dir: &Path, settings: ListenerSettings) -> Result<Runtime, Box<dyn std::error::Error>> {
    let spool_dir = dir.join("spool");
    fs::create_dir_all(&spool_dir)?;
    let spool = open_spool(
        &spool_dir,
        SpoolConfig {
            segment_max_bytes: MAX_FRAME_BYTES,
            total_max_bytes: MAX_FRAME_BYTES * SEGMENTS_IN_TOTAL,
        },
    )?;
    Ok(open_runtime(Arc::new(settings), spool)?)
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "collector".to_owned(),
        tenant: "acme".to_owned(),
        module: "site-collector".to_owned(),
        target: "settings".to_owned(),
        request_id: "test".to_owned(),
    }
}


fn write_settings(path: &Path, listen: &str, rate: u64) -> io::Result<()> {
    fs::write(path, format!("listen: \"{listen}\"\ntenant: acme\nrate_per_second: {rate}\n"))
}


struct Opened {
    engine: ReloadEngine<ListenerSettings>,
    shared: Arc<SharedSocket>,
    file: PathBuf,
    audit: PathBuf,
}


fn open_in(dir: &Path, listen: &str) -> Result<Opened, Box<dyn std::error::Error>> {
    let file = dir.join("listener.yaml");
    let audit = dir.join("audit.log");
    write_settings(&file, listen, DEFAULT_RATE_PER_SECOND)?;
    let log = open_file_log(&audit)?;
    let (engine, shared) = open_listener_engine(file.clone(), Box::new(move |entry| append(&log, entry)), context())?;
    Ok(Opened { engine, shared, file, audit })
}


fn idle_engine(settings: ListenerSettings) -> Result<ReloadEngine<ListenerSettings>, Box<dyn std::error::Error>> {
    Ok(open_engine(
        Box::new(move || Ok(settings.clone())),
        settings_state,
        Vec::new(),
        Box::new(|_entry| Err(core_audit::error::AuditError::Io(io::Error::from(ErrorKind::Other)))),
        context(),
    )?)
}


#[test]
fn settings_defaults_and_unknown_fields() -> TestResult {
    let dir = TempDir::new()?;
    let file = dir.path().join("s.yaml");
    fs::write(&file, "listen: \"127.0.0.1:0\"\ntenant: acme\n")?;
    let loaded = settings_loader(file.clone())()?;
    assert_eq!(loaded, settings());
    fs::write(&file, "listen: \"127.0.0.1:0\"\ntenant: acme\nextra: 1\n")?;
    assert!(settings_loader(file)().is_err());
    Ok(())
}


#[test]
fn validation_refuses_bad_settings() -> TestResult {
    assert!(validate_settings(&settings()).is_ok());
    let no_tenant = ListenerSettings {
        tenant: String::new(),
        ..settings()
    };
    assert!(matches!(validate_settings(&no_tenant), Err(ListenError::BadTenant)));
    let long_tenant = ListenerSettings {
        tenant: "t".repeat(MAX_TENANT_BYTES + 1),
        ..settings()
    };
    assert!(matches!(validate_settings(&long_tenant), Err(ListenError::BadTenant)));
    let no_rate = ListenerSettings {
        rate_per_second: 0,
        ..settings()
    };
    assert!(matches!(validate_settings(&no_rate), Err(ListenError::Limits(_))));
    let bad_address = ListenerSettings {
        listen: "nowhere".to_owned(),
        ..settings()
    };
    assert!(matches!(validate_settings(&bad_address), Err(ListenError::BadAddress(_))));
    assert!(parse_listen("127.0.0.1:514").is_ok());
    assert!(matches!(bind_socket("192.0.2.1:0".parse()?), Err(ListenError::Bind(_))));
    Ok(())
}


#[test]
fn ipv6_sources_count_by_their_64() -> TestResult {
    let first: IpAddr = "2001:db8:1:2:aaaa::1".parse()?;
    let second: IpAddr = "2001:db8:1:2:bbbb::9".parse()?;
    let other: IpAddr = "2001:db8:1:3::1".parse()?;
    assert_eq!(source_key(first), source_key(second));
    assert_ne!(source_key(first), source_key(other));
    assert_eq!(source_key(first), IpAddr::V6("2001:db8:1:2::".parse::<Ipv6Addr>()?));
    let mapped: IpAddr = "::ffff:192.0.2.7".parse()?;
    assert_eq!(source_key(mapped), "192.0.2.7".parse::<IpAddr>()?);
    let declared = ListenerSettings {
        sources: vec![first],
        ..settings()
    };
    assert!(collector_config_of(&declared).sources.contains(&source_key(second)));
    assert_eq!(settings_state(&declared).get("listener.tenant"), Some(&"\"acme\"".to_owned()));
    Ok(())
}


#[test]
fn admitted_records_reach_the_spool_by_severity() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), settings())?;
    handle_datagram(&mut runtime, source(1), LINE.as_bytes(), 0, YEAR);
    handle_datagram(&mut runtime, source(1), LOW_LINE.as_bytes(), 0, YEAR);
    handle_datagram(&mut runtime, source(1), b"garbage", 0, YEAR);
    let records = read_from(&runtime.spool, 0, FLOOD)?;
    assert_eq!(records.len() as u64, TWO);
    assert_eq!(records.first().map(|record| record.priority), Some(Priority::High));
    assert_eq!(records.get(1).map(|record| record.priority), Some(Priority::Low));
    assert_eq!(records.first().map(|record| record.payload.as_slice()), Some(LINE.as_bytes()));
    assert_eq!(
        (runtime.stats.received, runtime.stats.accepted, runtime.stats.dropped_parse),
        (THREE, TWO, 1)
    );
    assert_eq!(priority_of(0), Priority::High);
    assert_eq!(priority_of(u8::MAX), Priority::Low);
    Ok(())
}


#[test]
fn a_datagram_never_chooses_the_tenant() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), settings())?;
    handle_datagram(&mut runtime, source(1), TENANT_LINE.as_bytes(), 0, YEAR);
    assert_eq!(runtime.stats.accepted, 1);
    assert_eq!(listener_tenant(&runtime), "acme");
    Ok(())
}


#[test]
fn drops_are_counted_by_reason() -> TestResult {
    let dir = TempDir::new()?;
    let limited = ListenerSettings {
        rate_per_second: 1,
        burst: TWO,
        source_share_percent: MAX_SHARE_PERCENT,
        unknown_share_percent: MAX_UNKNOWN_SHARE_PERCENT,
        max_sources: TABLE,
        drop_unknown: false,
        ..settings()
    };
    let mut runtime = runtime_in(dir.path(), limited)?;
    (0..FLOOD).for_each(|_| handle_datagram(&mut runtime, source(1), LINE.as_bytes(), 0, YEAR));
    assert_eq!(runtime.stats.accepted, 1);
    assert_eq!(runtime.stats.dropped_rate, FLOOD as u64 - 1);
    handle_datagram(&mut runtime, source(TWO_U8), LINE.as_bytes(), 0, YEAR);
    handle_datagram(&mut runtime, source(THREE_U8), LINE.as_bytes(), 0, YEAR);
    assert_eq!(runtime.stats.dropped_table_full, 1);
    assert_eq!(untracked_dropped(&runtime.collector), 1);
    let oversized = vec![b'a'; MAX_MESSAGE_BYTES + 1];
    handle_datagram(&mut runtime, source(1), &oversized, 0, YEAR);
    assert_eq!(runtime.stats.dropped_too_long, 1);
    assert_eq!(
        source_counters(&runtime.collector, &source(1).ip()).map(|counters| counters.dropped_size),
        Some(1)
    );
    let strict = ListenerSettings {
        drop_unknown: true,
        ..settings()
    };
    let mut strict_runtime = runtime_in(TempDir::new()?.path(), strict)?;
    handle_datagram(&mut strict_runtime, source(1), LINE.as_bytes(), 0, YEAR);
    assert_eq!(strict_runtime.stats.dropped_unknown, 1);
    let mut counted = site_collector::listen_model::ListenerStats::default();
    count_reason(&mut counted, DropReason::GlobalRate);
    assert_eq!(counted.dropped_rate, 1);
    let mut saturated = u64::MAX;
    bump(&mut saturated);
    assert_eq!(saturated, u64::MAX);
    Ok(())
}


#[test]
fn a_failing_spool_is_counted() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), settings())?;
    fs::remove_dir_all(dir.path().join("spool"))?;
    let message = format!("{LINE} {}", "x".repeat(MAX_MESSAGE_BYTES / TWO as usize));
    (0..FLOOD).for_each(|_| handle_datagram(&mut runtime, source(1), message.as_bytes(), 0, YEAR));
    assert!(runtime.stats.spool_errors > 0);
    assert_eq!(runtime.stats.accepted + runtime.stats.spool_errors, FLOOD as u64);
    Ok(())
}


#[test]
fn the_receive_cycle_handles_every_read_result() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), settings())?;
    let engine = idle_engine(settings())?;
    let mut buffer = vec![0u8; MAX_MESSAGE_BYTES + 1];
    let now = || 0;
    let year = || YEAR;
    let mut datagram = |target: &mut [u8]| {
        target.fill(b'a');
        Ok((target.len(), source(1)))
    };
    receive_cycle(&mut runtime, &engine, &mut buffer, &mut datagram, &now, &year);
    assert_eq!(runtime.stats.dropped_too_long, 1);
    let mut valid = |target: &mut [u8]| {
        target.fill(0);
        target.iter_mut().zip(LINE.bytes()).for_each(|(slot, byte)| *slot = byte);
        Ok((LINE.len(), source(1)))
    };
    receive_cycle(&mut runtime, &engine, &mut buffer, &mut valid, &now, &year);
    assert_eq!(runtime.stats.accepted, 1);
    let mut blocked = |_target: &mut [u8]| Err(io::Error::from(ErrorKind::WouldBlock));
    receive_cycle(&mut runtime, &engine, &mut buffer, &mut blocked, &now, &year);
    let mut timed_out = |_target: &mut [u8]| Err(io::Error::from(ErrorKind::TimedOut));
    receive_cycle(&mut runtime, &engine, &mut buffer, &mut timed_out, &now, &year);
    assert_eq!(runtime.stats.receive_errors, 0);
    let mut broken = |_target: &mut [u8]| Err(io::Error::from(ErrorKind::PermissionDenied));
    receive_cycle(&mut runtime, &engine, &mut buffer, &mut broken, &now, &year);
    assert_eq!(runtime.stats.receive_errors, 1);
    Ok(())
}


#[test]
fn idle_sources_are_pruned_on_schedule() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), settings())?;
    handle_datagram(&mut runtime, source(1), LINE.as_bytes(), 0, YEAR);
    assert_eq!(tracked_sources(&runtime.collector), 1);
    prune_if_due(&mut runtime, PRUNE_INTERVAL_MS - 1);
    assert_eq!(tracked_sources(&runtime.collector), 1);
    prune_if_due(&mut runtime, site_collector::listen_model::IDLE_SOURCE_MS + PRUNE_INTERVAL_MS);
    assert_eq!(tracked_sources(&runtime.collector), 0);
    Ok(())
}


#[test]
fn a_reload_rebinds_and_changes_limits() -> TestResult {
    let dir = TempDir::new()?;
    let opened = open_in(dir.path(), "127.0.0.1:0")?;
    let mut runtime = runtime_in(dir.path(), settings())?;
    write_settings(&opened.file, "127.0.0.1:0", NEW_RATE)?;
    assert!(matches!(reload(&opened.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(opened.shared.bound.load().listen, "127.0.0.1:0");
    sync_settings(&mut runtime, &opened.engine);
    assert_eq!(collector_config(&runtime.collector).global.rate_per_second, NEW_RATE);
    let before = opened.shared.bound.load().socket.local_addr()?;
    write_settings(&opened.file, "127.0.0.2:0", NEW_RATE)?;
    assert!(matches!(reload(&opened.engine), ReloadOutcome::Applied { .. }));
    let after = opened.shared.bound.load().socket.local_addr()?;
    assert_eq!(after.ip(), "127.0.0.2".parse::<IpAddr>()?);
    assert_ne!(before.ip(), after.ip());
    Ok(())
}


#[test]
fn a_failed_bind_keeps_the_old_socket_and_is_audited() -> TestResult {
    let dir = TempDir::new()?;
    let opened = open_in(dir.path(), "127.0.0.1:0")?;
    let before = opened.shared.bound.load().socket.local_addr()?;
    write_settings(&opened.file, "192.0.2.1:0", DEFAULT_RATE_PER_SECOND)?;
    assert!(matches!(reload(&opened.engine), ReloadOutcome::Refused { .. }));
    assert_eq!(opened.shared.bound.load().socket.local_addr()?, before);
    assert_eq!(opened.shared.bound.load().listen, "127.0.0.1:0");
    let audit = fs::read_to_string(&opened.audit)?;
    assert!(audit.contains("refused"));
    write_settings(&opened.file, "127.0.0.1:0", DEFAULT_RATE_PER_SECOND + 1)?;
    assert!(matches!(reload(&opened.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(opened.shared.bound.load().socket.local_addr()?, before);
    Ok(())
}


#[test]
fn opening_refuses_unusable_settings() -> TestResult {
    let dir = TempDir::new()?;
    let missing = open_listener_engine(
        dir.path().join("none.yaml"),
        Box::new(|_entry| Err(core_audit::error::AuditError::Io(io::Error::from(ErrorKind::Other)))),
        context(),
    );
    assert!(matches!(missing, Err(ListenError::Settings(_))));
    let file = dir.path().join("bad.yaml");
    write_settings(&file, "nowhere", DEFAULT_RATE_PER_SECOND)?;
    let invalid = open_listener_engine(
        file,
        Box::new(|_entry| Err(core_audit::error::AuditError::Io(io::Error::from(ErrorKind::Other)))),
        context(),
    );
    assert!(matches!(invalid, Err(ListenError::BadAddress(_))));
    Ok(())
}


#[test]
fn a_refused_limit_change_is_logged_and_skipped() -> TestResult {
    let dir = TempDir::new()?;
    let mut runtime = runtime_in(dir.path(), settings())?;
    let engine = idle_engine(ListenerSettings {
        rate_per_second: 0,
        ..settings()
    })?;
    sync_settings(&mut runtime, &engine);
    assert_eq!(collector_config(&runtime.collector).global.rate_per_second, DEFAULT_RATE_PER_SECOND);
    Ok(())
}


#[test]
fn shutdown_stops_the_loop_before_any_read() -> TestResult {
    let dir = TempDir::new()?;
    let opened = open_in(dir.path(), "127.0.0.1:0")?;
    let mut runtime = runtime_in(dir.path(), settings())?;
    let shutdown = AtomicBool::new(true);
    let reads = AtomicU64::new(0);
    let now = || reads.fetch_add(1, Ordering::Relaxed);
    run(&mut runtime, &opened.engine, &opened.shared, &shutdown, &now, &|| YEAR);
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    Ok(())
}


#[test]
fn the_loop_reads_a_real_datagram_then_stops() -> TestResult {
    let dir = TempDir::new()?;
    let opened = open_in(dir.path(), "127.0.0.1:0")?;
    let mut runtime = runtime_in(dir.path(), settings())?;
    let target = opened.shared.bound.load().socket.local_addr()?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.send_to(LINE.as_bytes(), target)?;
    sender.send_to(&vec![b'a'; BIG_DATAGRAM], target)?;
    let shutdown = AtomicBool::new(false);
    let cycles = AtomicU64::new(0);
    let now = || {
        let seen = cycles.fetch_add(1, Ordering::Relaxed) + 1;
        shutdown.store(seen >= TWO, Ordering::Relaxed);
        0
    };
    run(&mut runtime, &opened.engine, &opened.shared, &shutdown, &now, &|| YEAR);
    assert_eq!((runtime.stats.accepted, runtime.stats.dropped_too_long), (1, 1));
    assert_eq!(spool_stats(&runtime.spool).next_sequence, 1);
    Ok(())
}
