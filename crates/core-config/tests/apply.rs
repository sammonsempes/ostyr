#[path = "common/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::{Actor, ActorKind};
use core_audit::verify::verify;
use core_config::apply::{apply, ApplyContext};
use core_config::error::ApplyError;
use core_config::plan::{plan, Change, ChangeKind};
use core_config::types::{BoxError, ConfigState};
use std::cell::RefCell;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use types::TestResult;


#[derive(Clone)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);


impl Write for SharedBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned")).map(|mut inner| {
            inner.extend_from_slice(buffer);
            buffer.len()
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


const THREE_CHANGES: usize = 3;


fn state(items: &[(&str, &str)]) -> ConfigState {
    items.iter().map(|(key, text)| ((*key).to_owned(), (*text).to_owned())).collect()
}


fn context() -> ApplyContext {
    ApplyContext {
        actor: Actor {
            kind: ActorKind::User,
            id: "alice".to_owned(),
        },
        tenant: "t".to_owned(),
        module: "core-config".to_owned(),
        request_id: "r1".to_owned(),
        justification: "ticket 42".to_owned(),
    }
}


fn apply_to(store: &RefCell<ConfigState>, change: &Change) -> io::Result<()> {
    let mut map = store.borrow_mut();
    match change.kind {
        ChangeKind::Delete => {
            map.remove(&change.key);
        }
        ChangeKind::Create | ChangeKind::Update => {
            map.insert(change.key.clone(), change.after.clone());
        }
    }
    Ok(())
}


fn shared() -> SharedBuffer {
    SharedBuffer(Arc::new(Mutex::new(Vec::new())))
}


#[test]
fn apply_writes_audit_records_and_verifies_read_back() -> TestResult {
    let desired = state(&[("a", "1\n"), ("b", "2\n")]);
    let store = RefCell::new(state(&[("b", "old\n"), ("c", "3\n")]));
    let changes = plan(&desired, &store.borrow());
    let buffer = shared();
    let log = genesis_log(buffer.clone());
    let report = apply(
        &changes,
        &desired,
        &context(),
        &mut |entry| append(&log, entry),
        &mut |change| apply_to(&store, change).map_err(BoxError::from),
        &mut || Ok(store.borrow().clone()),
    )?;
    assert_eq!(report.applied, vec!["a", "b", "c"]);
    assert_eq!(*store.borrow(), desired);
    let bytes = buffer.0.lock().map_err(|_| "poisoned")?.clone();
    let text = String::from_utf8(bytes.clone())?;
    assert_eq!(verify(bytes.as_slice(), None)?.records, THREE_CHANGES);
    assert!(text.contains("config.create") && text.contains("config.update") && text.contains("config.delete"));
    assert!(text.contains("alice") && text.contains("ticket 42") && text.contains("--- a/b"));
    Ok(())
}


#[test]
fn empty_plan_applies_nothing() -> TestResult {
    let desired = state(&[("a", "1\n")]);
    let log = genesis_log(Vec::new());
    let report = apply(
        &Vec::new(),
        &desired,
        &context(),
        &mut |entry| append(&log, entry),
        &mut |_| Err(io::Error::other("never").into()),
        &mut || Ok(desired.clone()),
    )?;
    assert!(report.applied.is_empty());
    Ok(())
}


#[test]
fn failure_midway_stops_and_reports_applied() -> TestResult {
    let desired = state(&[("a", "1\n"), ("b", "2\n"), ("c", "3\n")]);
    let changes = plan(&desired, &ConfigState::new());
    let store = RefCell::new(ConfigState::new());
    let buffer = shared();
    let log = genesis_log(buffer.clone());
    let outcome = apply(
        &changes,
        &desired,
        &context(),
        &mut |entry| append(&log, entry),
        &mut |change| {
            if change.key == "b" {
                Err(io::Error::other("disk full").into())
            } else {
                apply_to(&store, change).map_err(BoxError::from)
            }
        },
        &mut || Ok(store.borrow().clone()),
    );
    match outcome {
        Err(ApplyError::Applier { key, applied, source }) => {
            assert_eq!(key, "b");
            assert_eq!(applied, vec!["a"]);
            assert!(source.to_string().contains("disk full"));
        }
        other => Err(format!("unexpected {other:?}"))?,
    }
    assert_eq!(store.borrow().len(), 1);
    assert_eq!(verify(buffer.0.lock().map_err(|_| "poisoned")?.as_slice(), None)?.records, 1);
    Ok(())
}


#[test]
fn applier_error_message_names_key_and_count() {
    let error = ApplyError::Applier {
        key: "k".to_owned(),
        applied: vec!["x".to_owned()],
        source: Box::new(io::Error::other("boom")),
    };
    assert_eq!(error.to_string(), "applying `k` failed after 1 change(s): boom");
}


#[test]
fn read_back_mismatch_is_an_error() -> TestResult {
    let desired = state(&[("a", "1\n"), ("b", "2\n")]);
    let changes = plan(&desired, &ConfigState::new());
    let outcome = apply(
        &changes,
        &desired,
        &context(),
        &mut |entry| append(&genesis_log(Vec::new()), entry),
        &mut |_| Ok(()),
        &mut || Ok(state(&[("a", "1\n")])),
    );
    match outcome {
        Err(error @ ApplyError::Mismatch { .. }) => assert!(error.to_string().contains('b')),
        other => Err(format!("unexpected {other:?}"))?,
    }
    Ok(())
}


#[test]
fn read_back_failure_is_an_error() -> TestResult {
    let desired = state(&[("a", "1\n")]);
    let outcome = apply(
        &Vec::new(),
        &desired,
        &context(),
        &mut |entry| append(&genesis_log(Vec::new()), entry),
        &mut |_| Ok(()),
        &mut || Err(io::Error::other("unreadable").into()),
    );
    match outcome {
        Err(error @ ApplyError::ReadBack(_)) => assert!(error.to_string().contains("unreadable")),
        other => Err(format!("unexpected {other:?}"))?,
    }
    Ok(())
}


#[test]
fn audit_failure_is_an_error() -> TestResult {
    let desired = state(&[("a", "1\n")]);
    let changes = plan(&desired, &ConfigState::new());
    let outcome = apply(
        &changes,
        &desired,
        &context(),
        &mut |entry| append(&genesis_log(FailingWriter), entry),
        &mut |_| Ok(()),
        &mut || Ok(desired.clone()),
    );
    match outcome {
        Err(
            error @ ApplyError::Audit {
                source: AuditError::Io(_), ..
            },
        ) => assert!(error.to_string().contains("audit failed")),
        other => Err(format!("unexpected {other:?}"))?,
    }
    Ok(())
}
