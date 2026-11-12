use std::sync::LazyLock;
use tracing::Dispatch;


pub static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


pub fn capture_dispatch<Maker>(make_writer: Maker) -> Dispatch
where
    Maker: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    LazyLock::force(&ANCHOR);
    Dispatch::new(tracing_subscriber::fmt().with_writer(make_writer).with_ansi(false).finish())
}
