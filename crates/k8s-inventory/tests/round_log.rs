#[path = "common/types.rs"]
mod types;


use cmdb::error::StoreError;
use k8s_inventory::error::SyncError;
use k8s_inventory::round::{fault_class, log_round, RoundFault, PARTIAL_CLASS, UNKNOWN_CLASS};
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use tracing::Dispatch;
use types::TestResult;


const PAGES: usize = 2;


const CREATED: usize = 93;


const UPDATED: usize = 7;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn logged(fault: RoundFault) -> Result<String, Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = buffer.clone();
    let guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Capture(writer.clone()))
            .finish(),
    );
    log_round(&Err(fault));
    drop(guard);
    let bytes = buffer.lock().unwrap_or_else(PoisonError::into_inner).clone();
    Ok(String::from_utf8(bytes)?)
}


#[test]
fn a_partly_synced_round_names_its_counts_and_the_failure_and_never_claims_the_last_sync() -> TestResult {
    let partial = SyncError::Partial {
        pages: PAGES,
        created: CREATED,
        updated: UPDATED,
        conflicts: 0,
        source: StoreError::VersionConflict,
    };
    assert_eq!(
        fault_class(&RoundFault::Sync(SyncError::Partial {
            pages: 1,
            created: 1,
            updated: 0,
            conflicts: 0,
            source: StoreError::VersionConflict
        })),
        PARTIAL_CLASS
    );
    let line = logged(RoundFault::Sync(partial))?;
    assert!(line.contains("partly synced: pages=2 created=93 updated=7 conflicts=0"), "{line}");
    assert!(line.contains("cmdb_partial"), "{line}");
    assert!(line.contains("partial sync"), "{line}");
    assert!(!line.contains("keeps the last sync"), "{line}");
    let plain = logged(RoundFault::Sync(SyncError::Store(StoreError::VersionConflict)))?;
    assert!(plain.contains("keeps the last sync") && plain.contains("cmdb_sync"), "{plain}");
    Ok(())
}


#[test]
fn an_unknown_outcome_is_its_own_class_and_never_claims_the_last_sync() -> TestResult {
    let unknown = || SyncError::Unknown {
        pages: PAGES,
        created: CREATED,
        updated: UPDATED,
        conflicts: 0,
        cause: "client_deadline",
    };
    assert_eq!(fault_class(&RoundFault::Sync(unknown())), UNKNOWN_CLASS);
    let line = logged(RoundFault::Sync(unknown()))?;
    assert!(line.contains("cmdb_unknown"), "{line}");
    assert!(line.contains("the CMDB may hold the failed page or not"), "{line}");
    assert!(line.contains("pages=2 created=93 updated=7"), "{line}");
    assert!(!line.contains("keeps the last sync"), "{line}");
    Ok(())
}
