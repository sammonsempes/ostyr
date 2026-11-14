use std::fs;
use std::path::Path;


const CAP_FEATURES: [&str; 2] = ["max_level_debug", "release_max_level_debug"];


fn dependency_line<'a>(manifest: &'a str, name: &str) -> Option<&'a str> {
    manifest
        .lines()
        .find(|line| line.split('=').next().is_some_and(|key| key.trim() == name) && line.contains('='))
}


#[test]
pub fn every_crate_that_depends_on_ureq_caps_the_log_level() -> anyhow::Result<()> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates");
    let manifests = fs::read_dir(&crates)?
        .map(|entry| entry.map(|found| found.path().join("Cargo.toml")))
        .collect::<Result<Vec<_>, _>>()?;
    let uncapped = manifests
        .iter()
        .filter(|path| path.is_file())
        .map(|path| fs::read_to_string(path).map(|text| (path.clone(), text)))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|(_, text)| dependency_line(text, "ureq").is_some())
        .filter(|(_, text)| {
            let capped = dependency_line(text, "log").is_some_and(|line| CAP_FEATURES.iter().all(|feature| line.contains(feature)));
            !capped
        })
        .map(|(path, _)| path.display().to_string())
        .collect::<Vec<_>>();
    assert!(uncapped.is_empty(), "ureq crates without the log cap: {uncapped:?}");
    Ok(())
}
