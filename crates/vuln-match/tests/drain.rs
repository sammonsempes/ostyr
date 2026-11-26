#![cfg(unix)]


#[path = "common/pg.rs"]
mod pg;
#[path = "common/site.rs"]
mod site;
#[path = "common/types.rs"]
mod types;


use core_config::types::SharedAuditFn;
use pg::{fake_with, scanning};
use signal_hook::consts::SIGHUP;
use site::{write_site, VULNERABLE};
use std::fs;
use std::future::pending;
use std::pin::Pin;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;
use tokio::sync::oneshot;
use types::TestResult;
use vuln_match::serve::{serving_with, Hooks};
use vuln_match::service::load_settings;
use vuln_match::types::InterruptWait;


const HANG_GUARD: Duration = Duration::from_secs(120);


const SERVED_POLLS: usize = 100;


const SERVED_POLL: Duration = Duration::from_millis(10);


const NOW: u64 = 1_700_000_000_000_000;


fn fixed_now() -> u64 {
    NOW
}


fn never_wakes(_duration: Duration) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(pending())
}


fn mark(events: &Mutex<Vec<&'static str>>, name: &'static str) {
    if let Ok(mut list) = events.lock() {
        list.push(name);
    }
}


fn wait_on(receiver: &Mutex<Receiver<()>>) {
    if let Ok(guard) = receiver.lock() {
        assert!(guard.recv_timeout(HANG_GUARD).is_ok(), "hang guard");
    }
}


/// A reload held inside its audit write while the interrupt arrives: the service returns only after that record is written.
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_in_flight_finishes_its_audit_record_before_the_service_returns() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (fake, ca_pem) = fake_with(scanning()).await?;
    let site = write_site(dir.path(), fake.port, &ca_pem)?;
    fs::write(site.inventory.join("web-1.json"), VULNERABLE)?;
    let events: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let (entered_tx, entered) = channel::<()>();
    let (release_sender, release_rx) = channel::<()>();
    let (woke_tx, woke_rx) = channel::<()>();
    let (ready_sender, ready_receiver) = channel::<()>();
    let (draining_sender, draining) = channel::<()>();
    let release_gate = Arc::new(Mutex::new(release_rx));
    let woke_gate = Arc::new(Mutex::new(woke_rx));
    let (stop_sender, stop_receiver) = oneshot::channel::<()>();
    let settings_file = site.settings.clone();
    let served_events = Arc::clone(&events);
    let audit_events = Arc::clone(&events);
    let drain_events = Arc::clone(&events);
    let worker = spawn(move || -> Result<(), String> {
        let wrap = move |inner: Box<SharedAuditFn>| -> Box<SharedAuditFn> {
            let release_in = Arc::clone(&release_gate);
            let entered_in: Sender<()> = entered_tx.clone();
            let woke_in: Sender<()> = woke_tx.clone();
            let events_in = Arc::clone(&audit_events);
            Box::new(move |entry| {
                assert!(entered_in.send(()).is_ok());
                wait_on(&release_in);
                assert!(woke_in.send(()).is_ok());
                let polls = (0..SERVED_POLLS)
                    .take_while(|_| {
                        std::thread::sleep(SERVED_POLL);
                        events_in.lock().is_ok_and(|list| !list.contains(&"served"))
                    })
                    .count();
                assert!(polls <= SERVED_POLLS);
                let record = inner(entry);
                mark(&events_in, "audit_written");
                record
            })
        };
        let ready_hook = move || assert!(ready_sender.send(()).is_ok());
        let before_drain = {
            let woke_in = Arc::clone(&woke_gate);
            move || {
                assert!(draining_sender.send(()).is_ok());
                wait_on(&woke_in);
            }
        };
        let hooks = Hooks {
            wrap_audit: &wrap,
            ready: &ready_hook,
            before_drain: &before_drain,
        };
        let interrupt: InterruptWait = Box::pin(async move {
            match stop_receiver.await {
                Ok(()) | Err(_) => (),
            }
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        let ended = runtime
            .block_on(serving_with(
                load_settings,
                &settings_file,
                u64::MAX,
                &fixed_now,
                &never_wakes,
                interrupt,
                &hooks,
            ))
            .map_err(|error| error.to_string())?;
        mark(&served_events, "served");
        assert_eq!(format!("{ended:?}"), "Interrupted");
        Ok(())
    });
    assert!(ready_receiver.recv_timeout(HANG_GUARD).is_ok(), "the service never became ready");
    let base = fs::read_to_string(&site.settings)?;
    fs::write(&site.settings, base.replace("round_seconds: 10", "round_seconds: 30"))?;
    assert!(signal_hook::low_level::raise(SIGHUP).is_ok());
    assert!(entered.recv_timeout(HANG_GUARD).is_ok(), "no reload reached its audit");
    assert!(stop_sender.send(()).is_ok());
    assert!(draining.recv_timeout(HANG_GUARD).is_ok(), "the service never reached its drain");
    assert!(release_sender.send(()).is_ok());
    worker.join().map_err(|_panic| "the worker panicked")??;
    let order = drain_events.lock().map_err(|_poisoned| "poisoned")?.clone();
    assert_eq!(
        order,
        ["audit_written", "served"],
        "the service returned before the reload's record was written"
    );
    let audit = fs::read_to_string(&site.audit)?;
    assert!(audit.contains("config.reload") && audit.contains("\"all\""), "{audit}");
    Ok(())
}
