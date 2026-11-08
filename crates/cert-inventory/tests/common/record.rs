use cert_inventory::model::{CertRecord, KeyType};


pub fn record_with(dns_names: &[&str], not_after: i64) -> CertRecord {
    CertRecord {
        fingerprint_sha256: String::new(),
        subject: String::new(),
        issuer: String::new(),
        dns_names: dns_names.iter().map(|name| (*name).to_string()).collect(),
        not_before: 0,
        not_after,
        key_type: KeyType::Other,
        key_bits: None,
        self_signed: true,
    }
}
