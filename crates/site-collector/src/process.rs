use crate::admission::{admit, slot};
use crate::error::ParseError;
use crate::model::{Collector, Outcome, SyslogRecord};
use crate::parse::parse_syslog;
use crate::types::{Millis, SourceId};


fn record_result(collector: &mut Collector, source: SourceId, now: Millis, result: Result<SyslogRecord, ParseError>) -> Outcome {
    let counters = &mut slot(&mut collector.sources, &collector.source_limits, source, now).counters;
    match result {
        Ok(record) => {
            counters.accepted = counters.accepted.saturating_add(1);
            Outcome::Accepted(record)
        }
        Err(error) => {
            counters.parse_errors = counters.parse_errors.saturating_add(1);
            tracing::debug!(%source, %error, "syslog message rejected");
            Outcome::Malformed(error)
        }
    }
}


pub fn process_datagram(collector: &mut Collector, source: SourceId, payload: &[u8], now: Millis, year: i32) -> Outcome {
    match admit(collector, source, payload.len(), now) {
        Err(reason) => Outcome::Dropped(reason),
        Ok(()) => record_result(collector, source, now, parse_syslog(payload, year)),
    }
}
