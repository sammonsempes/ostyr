use crate::config::DEFAULT_LOG_LEVEL;
use crate::types::LogLevelHandle;
use tracing::level_filters::LevelFilter;
use tracing::Dispatch;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, reload, Registry};


/// One JSON object per event, event fields at the top level (spec section 13); the handle changes the level while running.
pub fn reloadable_dispatch(writer: BoxMakeWriter, level: LevelFilter) -> (Dispatch, LogLevelHandle) {
    let (filter, handle) = reload::Layer::new(level);
    let output = fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(writer);
    (Dispatch::new(Registry::default().with(filter).with(output)), handle)
}


pub fn json_dispatch(writer: BoxMakeWriter) -> Dispatch {
    reloadable_dispatch(writer, DEFAULT_LOG_LEVEL).0
}
