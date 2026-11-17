//! The service's log subscriber: siem-ingest's (the `async_nats` target dropped), INFO by default so `tokio_postgres` never logs SQL.
use siem_ingest::logging::build_subscriber;
use tracing::Subscriber;
use tracing_subscriber::filter::ParseError;
use tracing_subscriber::fmt::MakeWriter;


pub const DEFAULT_DIRECTIVES: &str = "info";


/// Operator directives (the `RUST_LOG` text) or INFO, with the async-nats target dropped.
pub fn service_subscriber<Writer>(writer: Writer, directives: Option<&str>) -> Result<impl Subscriber + Send + Sync, ParseError>
where
    Writer: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    build_subscriber(writer, Some(directives.unwrap_or(DEFAULT_DIRECTIVES)))
}
