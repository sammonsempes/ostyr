use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;
use walkdir::WalkDir;


const BRIDGE_MARKERS: [&str; 6] = ["LogTracer", "tracing_log", "fmt::init(", ".init()", ".try_init()", ".set_default("];


const PLATFORM_FILE: &str = "crates/platform/src/serve.rs";


const PLAYBOOKS_FILE: &str = "crates/response-playbooks/src/serve.rs";


const FILTERED_BRIDGE_FILES: [&str; 2] = [PLATFORM_FILE, PLAYBOOKS_FILE];


const FILTERED_CALL: &str = ".ignore_crate(LOG_IGNORED_CRATE).init()";


const OWN_CONSTANT: &str = "const LOG_IGNORED_CRATE";


const CALL_MARKERS: [&str; 4] = ["::init", ".init()", ".try_init()", ".set_default("];


pub fn installs_bridge(text: &str) -> bool {
    BRIDGE_MARKERS.iter().any(|marker| text.contains(marker))
}


pub fn code_lines(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn is_filtered_bridge(relative: &Path, text: &str) -> bool {
    let code = code_lines(text);
    let calls: usize = CALL_MARKERS.iter().map(|marker| code.matches(marker).count()).sum();
    let filtered = code.matches(FILTERED_CALL).count();
    FILTERED_BRIDGE_FILES.iter().any(|file| relative == Path::new(file)) && filtered > 0 && calls == filtered && !code.contains(OWN_CONSTANT)
}


#[test]
fn only_the_two_listed_services_may_bridge_and_only_with_the_filter() -> Result<(), Box<dyn Error>> {
    let bridge = "tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;";
    let platform = Path::new(PLATFORM_FILE);
    assert!(is_filtered_bridge(platform, bridge));
    assert!(!is_filtered_bridge(platform, "tracing_log::LogTracer::init()"));
    assert!(is_filtered_bridge(Path::new(PLAYBOOKS_FILE), bridge));
    assert!(!is_filtered_bridge(Path::new("crates/other/src/serve.rs"), bridge));
    Ok(())
}


#[test]
fn survivor_second_unfiltered_bridge_is_refused() -> Result<(), Box<dyn Error>> {
    let text = "tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;\ntracing_log::LogTracer::init()?;";
    assert!(!is_filtered_bridge(Path::new(PLATFORM_FILE), text));
    Ok(())
}


#[test]
fn survivor_marker_only_in_a_comment_is_refused() -> Result<(), Box<dyn Error>> {
    let text = "/// tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()\nfn f() { LogTracer::init(); }";
    assert!(!is_filtered_bridge(Path::new(PLATFORM_FILE), text));
    Ok(())
}


#[test]
fn survivor_local_constant_is_refused() -> Result<(), Box<dyn Error>> {
    let text = "const LOG_IGNORED_CRATE: &str = \"none\";\nLogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;";
    assert!(!is_filtered_bridge(Path::new(PLATFORM_FILE), text));
    Ok(())
}


#[test]
fn the_allowed_list_is_exactly_the_two_services() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        FILTERED_BRIDGE_FILES,
        ["crates/platform/src/serve.rs", "crates/response-playbooks/src/serve.rs"]
    );
    Ok(())
}


#[test]
fn survivor_a_third_path_is_refused() -> Result<(), Box<dyn Error>> {
    let text = "LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;";
    assert!(!is_filtered_bridge(Path::new("crates/web-ui/src/serve.rs"), text));
    assert!(!is_filtered_bridge(
        Path::new("crates/response-playbooks/src/bin/ostyr-playbooks.rs"),
        text
    ));
    assert!(!is_filtered_bridge(Path::new("crates/response-playbooks/src/service.rs"), text));
    Ok(())
}


#[test]
fn survivor_nested_path_is_refused() -> Result<(), Box<dyn Error>> {
    let text = "LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;";
    assert!(!is_filtered_bridge(Path::new("crates/cmdb/src/platform/src/serve.rs"), text));
    assert!(!is_filtered_bridge(Path::new("x/crates/platform/src/serve.rs"), text));
    Ok(())
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


pub fn workspace_relative(path: &Path) -> std::path::PathBuf {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    Path::new("crates").join(path.strip_prefix(crates).unwrap_or(path))
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
            Ok(true) if read_text(entry.path()).is_ok_and(|text| is_filtered_bridge(&workspace_relative(entry.path()), &text)) => None,
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
