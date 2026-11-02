use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use std::error::Error;
use time::OffsetDateTime;


pub const BASE_TIMESTAMP: i64 = 1_700_000_000;


pub fn entry(index: usize) -> Result<NewEntry, Box<dyn Error>> {
    let offset = i64::try_from(index)?;
    Ok(NewEntry {
        timestamp: OffsetDateTime::from_unix_timestamp(BASE_TIMESTAMP + offset)?,
        actor: Actor {
            kind: ActorKind::User,
            id: format!("user-{index}"),
        },
        tenant: "tenant-a".to_owned(),
        module: "iam".to_owned(),
        action: "config.update".to_owned(),
        target: format!("setting-{index}"),
        outcome: Outcome::Success,
        request_id: format!("request-{index}"),
        justification: Some("ticket 42".to_owned()),
        parameters: [("name".to_owned(), "value".to_owned())].into(),
    })
}
