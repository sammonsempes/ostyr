use crate::error::StatusPageError;
use crate::model::{PageState, RenderedPage, Snapshot};
use sha2::{Digest, Sha256};
use std::sync::Arc;


/// The ETag is the quoted SHA-256 of the JSON and the HTML, so it changes exactly when a served byte does.
pub fn etag_of(json: &str, html: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(json.as_bytes());
    digest.update(html.as_bytes());
    format!("\"{:x}\"", digest.finalize())
}


pub fn snapshot_of(tenant: &str, rendered: &RenderedPage) -> Snapshot {
    Snapshot {
        tenant: tenant.to_owned(),
        html: rendered.html.clone(),
        json: rendered.json.clone(),
        etag: etag_of(&rendered.json, &rendered.html),
    }
}


/// Swaps the served page atomically; a snapshot of another tenant is refused and the old one stays.
pub fn publish(state: &PageState, snapshot: Snapshot) -> Result<(), StatusPageError> {
    if snapshot.tenant == state.tenant {
        state.snapshot.store(Some(Arc::new(snapshot)));
        Ok(())
    } else {
        Err(StatusPageError::SnapshotTenant {
            page: state.tenant.clone(),
            snapshot: snapshot.tenant,
        })
    }
}
