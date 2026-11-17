//! The one log subscriber every binary linking async-nats builds: the library logs peer certificate names raw at DEBUG, so its target is capped.
use std::str::FromStr;
use tracing::{Level, Subscriber};
use tracing_subscriber::filter::{filter_fn, ParseError, Targets};
use tracing_subscriber::fmt::{self, MakeWriter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, Registry};


pub const CAPPED_TARGET: &str = "async_nats";


pub const CAPPED_PREFIX: &str = "async_nats::";


pub const CAPPED_LEVEL: Level = Level::INFO;


pub const DEFAULT_DIRECTIVES: &str = "debug";


/// True for the async-nats crate and every module of it.
pub fn is_capped_target(target: &str) -> bool {
    target == CAPPED_TARGET || target.starts_with(CAPPED_PREFIX)
}


/// The cap applies after the operator's directives, so no directive can raise an async-nats event above INFO.
pub fn log_allowed(targets: &Targets, target: &str, level: &Level) -> bool {
    targets.would_enable(target, level) && !(is_capped_target(target) && level > &CAPPED_LEVEL)
}


/// Operator directives (the `RUST_LOG` text, DEBUG for everything when absent) under the async-nats cap.
pub fn build_subscriber<Writer>(writer: Writer, directives: Option<&str>) -> Result<impl Subscriber + Send + Sync, ParseError>
where
    Writer: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let targets = Targets::from_str(directives.unwrap_or(DEFAULT_DIRECTIVES))?;
    let filter = filter_fn(move |metadata| log_allowed(&targets, metadata.target(), metadata.level()));
    Ok(Registry::default().with(fmt::layer().with_ansi(false).with_writer(writer).with_filter(filter)))
}
