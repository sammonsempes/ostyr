use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::error::Error;
use std::sync::Arc;


pub const PG_PASSWORD: &str = "p";


/// Answers the scan with one inserted row and the alert insert with one new alert; everything else (migrations) is done.
pub fn scanning() -> Handler {
    Arc::new(|sql| {
        if sql.contains("vuln_scan_store(") {
            Reply::Rows(vec![["1", "0", "0", "0", "0", "0", "0"].map(str::to_owned).to_vec()])
        } else if sql.contains("jsonb_to_recordset($2") {
            Reply::Rows(vec![vec!["1".to_owned()]])
        } else {
            Reply::Done
        }
    })
}


pub async fn fake_with(handler: Handler) -> Result<(Fake, String), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}
