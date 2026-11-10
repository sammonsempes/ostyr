use std::error::Error;
use std::fs;
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


#[test]
fn no_crate_source_installs_a_log_bridge() -> Result<(), Box<dyn Error>> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let offenders: Vec<String> = WalkDir::new(&crates)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| entry.path().extension().is_some_and(|extension| extension == "rs"))
        .filter(|entry| entry.path().components().any(|part| part.as_os_str() == "src"))
        .filter(|entry| !entry.path().components().any(|part| part.as_os_str() == "target"))
        .filter(|entry| fs::read_to_string(entry.path()).is_ok_and(|text| installs_bridge(&text)))
        .map(|entry| entry.path().display().to_string())
        .collect();
    assert!(
        offenders.is_empty(),
        "tokio_postgres logs bound parameters at debug through `log`: {offenders:?}"
    );
    Ok(())
}
