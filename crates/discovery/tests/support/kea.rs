use core_export::ecs::{blank_event, EcsEvent, EndpointFields, EventFields, HostFields};
use std::error::Error;
use time::OffsetDateTime;


pub const LIFETIME: i64 = 3600;


pub fn lease_event(address: &str, mac: Option<&str>, hostname: Option<&str>, cltt: i64) -> Result<EcsEvent, Box<dyn Error>> {
    let mut event = lease_event_at(address, mac, hostname, cltt)?;
    event.event.end = Some(OffsetDateTime::from_unix_timestamp(cltt + LIFETIME)?);
    Ok(event)
}


pub fn lease_event_at(address: &str, mac: Option<&str>, hostname: Option<&str>, cltt: i64) -> Result<EcsEvent, Box<dyn Error>> {
    let start = OffsetDateTime::from_unix_timestamp(cltt)?;
    Ok(EcsEvent {
        event: EventFields {
            action: Some("lease-assigned".to_string()),
            dataset: Some("kea.lease".to_string()),
            start: Some(start),
            ..EventFields::default()
        },
        host: hostname.map(|name| HostFields {
            hostname: Some(name.to_string()),
            ..HostFields::default()
        }),
        source: Some(EndpointFields {
            ip: Some(address.to_string()),
            mac: mac.map(str::to_string),
            ..EndpointFields::default()
        }),
        ..blank_event(start)
    })
}
