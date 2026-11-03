use core_api::logging::json_dispatch;
use std::sync::LazyLock;
use tracing::Dispatch;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


pub static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


pub fn capture_dispatch(writer: BoxMakeWriter) -> Dispatch {
    LazyLock::force(&ANCHOR);
    json_dispatch(writer)
}
