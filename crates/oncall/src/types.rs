use crate::model::{Channel, Message};


pub type Sender<'sender> = &'sender mut dyn FnMut(&Channel, &Message) -> Result<(), String>;


pub type Headers = Vec<(&'static str, zeroize::Zeroizing<String>)>;


pub type ClockFn<'clock> = &'clock dyn Fn() -> std::time::Instant;


pub type Row = Vec<crate::alert::Cell>;


pub type FillFn = fn(&mut [u8]) -> Result<(), getrandom::Error>;


pub type IssueError = crate::error::LinkError<std::convert::Infallible>;


/// A signing key of at least `MIN_LINK_KEY_BYTES`; only `linkkey` builds one. No `Debug`: it is a secret.
pub struct LinkKey(pub(crate) zeroize::Zeroizing<Vec<u8>>);


pub type NowFn = fn() -> chrono::DateTime<chrono::Utc>;


pub type TenantOutcome = (String, Result<usize, crate::error::SourceError>);


pub type WaitFn = fn(std::time::Duration) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;


pub type ReportFn = fn(&[TenantOutcome]);
