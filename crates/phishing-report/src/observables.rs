use crate::model::Triage;
use cases::model::ObservableKind;
use std::collections::BTreeSet;
use url::Url;


fn domain_of(address: &str) -> Option<&str> {
    address.rsplit_once('@').map(|(_, domain)| domain)
}


/// The observables of one triage record, sorted and deduplicated: addresses, domains, URLs, attachment hashes and file names.
pub fn observables(record: &Triage) -> Vec<(ObservableKind, String)> {
    let addresses = record
        .sender
        .iter()
        .chain(record.return_path.iter())
        .chain(record.senders.iter())
        .map(|address| address.to_ascii_lowercase());
    let hosts = record
        .urls
        .iter()
        .flat_map(|hit| Url::parse(&hit.url).into_iter().filter_map(|parsed| parsed.domain().map(str::to_owned)));
    let domains = record
        .sender
        .iter()
        .chain(record.return_path.iter())
        .chain(record.senders.iter())
        .filter_map(|address| domain_of(address))
        .map(str::to_ascii_lowercase)
        .chain(hosts);
    let urls = record.urls.iter().map(|hit| (ObservableKind::Url, hit.url.clone()));
    let attachments = record.attachments.iter().flat_map(|attachment| {
        let name = attachment.file_name.iter().map(|name| (ObservableKind::Filename, name.clone()));
        name.chain(std::iter::once((ObservableKind::Hash, attachment.sha256.clone())))
    });
    addresses
        .map(|address| (ObservableKind::Email, address))
        .chain(domains.map(|domain| (ObservableKind::Domain, domain)))
        .chain(urls)
        .chain(attachments)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
