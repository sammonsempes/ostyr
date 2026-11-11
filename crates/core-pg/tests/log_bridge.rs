use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;
use walkdir::WalkDir;


const BRIDGE_MARKERS: [&str; 6] = ["LogTracer", "tracing_log", "fmt::init(", ".init()", ".try_init()", ".set_default("];


pub fn installs_bridge(text: &str) -> bool {
    BRIDGE_MARKERS.iter().any(|marker| text.contains(marker))
}


#[test]
fn the_probe_sources_are_flagged() -> Result<(), Box<dyn Error>> {
    assert!(installs_bridge("fn main() { tracing_subscriber::fmt::init(); }"));
    assert!(installs_bridge("tracing_subscriber::fmt().finish().try_init()?;"));
    assert!(installs_bridge("let guard = subscriber.set_default(x);"));
    assert!(installs_bridge("builder.init();"));
    assert!(installs_bridge("tracing_log::LogTracer::init()"));
    assert!(!installs_bridge("fn main() {}"));
    Ok(())
}


pub fn read_text(path: &Path) -> io::Result<String> {
    fs::read_to_string(path)
}


pub fn bridge_in_file(path: &Path, read: fn(&Path) -> io::Result<String>) -> Result<bool, String> {
    read(path)
        .map(|text| installs_bridge(&text))
        .map_err(|error| format!("{}: {error}", path.display()))
}


#[test]
fn an_unreadable_source_file_is_named_not_skipped() -> Result<(), Box<dyn Error>> {
    let failing: fn(&Path) -> io::Result<String> = |_| Err(io::Error::new(io::ErrorKind::InvalidData, "not utf-8"));
    let message = bridge_in_file(Path::new("crates/x/src/odd.rs"), failing)
        .err()
        .ok_or("expected an error")?;
    assert!(message.contains("crates/x/src/odd.rs"), "{message}");
    let flagged: fn(&Path) -> io::Result<String> = |_| Ok("LogTracer".to_owned());
    assert!(bridge_in_file(Path::new("a.rs"), flagged)?);
    Ok(())
}


#[test]
fn no_crate_source_installs_a_log_bridge() -> Result<(), Box<dyn Error>> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let sources: Vec<_> = WalkDir::new(&crates)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| entry.path().extension().is_some_and(|extension| extension == "rs"))
        .filter(|entry| entry.path().components().any(|part| part.as_os_str() == "src"))
        .filter(|entry| !entry.path().components().any(|part| part.as_os_str() == "target"))
        .collect();
    let offenders = sources
        .iter()
        .filter_map(|entry| match bridge_in_file(entry.path(), read_text) {
            Ok(true) => Some(Ok(entry.path().display().to_string())),
            Ok(false) => None,
            Err(message) => Some(Err(message)),
        })
        .collect::<Result<Vec<String>, String>>()?;
    assert!(
        offenders.is_empty(),
        "tokio_postgres logs bound parameters at debug through `log`: {offenders:?}"
    );
    Ok(())
}
