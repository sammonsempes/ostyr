use tracing::Dispatch;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


/// One JSON object per event, event fields at the top level (spec section 13).
pub fn json_dispatch(writer: BoxMakeWriter) -> Dispatch {
    Dispatch::new(
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_writer(writer)
            .finish(),
    )
}
