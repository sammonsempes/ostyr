//! Parses one or two SBOM files (SPDX or CycloneDX) and prints counts and, for two files, the diff: `sbom_parse <file> [<file>]`.

use sbom::diff::diff;
use sbom::model::{Limits, Sbom};
use sbom::parse::parse_document;
use std::io::Write;


fn load(path: &str) -> Result<Sbom, Box<dyn std::error::Error>> {
    Ok(parse_document(std::fs::File::open(path)?, "tenant-a", "artefact", &Limits::default())?)
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout();
    let paths: Vec<String> = std::env::args().skip(1).collect();
    let documents = paths.iter().map(|path| load(path)).collect::<Result<Vec<Sbom>, _>>()?;
    documents.iter().zip(&paths).try_for_each(|(sbom, path)| {
        writeln!(
            out,
            "{path}: components={} skipped={} bad_purls={} unmapped={} extra_purls={}",
            sbom.components.len(),
            sbom.skipped,
            sbom.bad_purls,
            sbom.unmapped,
            sbom.extra_purls
        )
    })?;
    documents.iter().try_for_each(|sbom| {
        sbom.components
            .iter()
            .try_for_each(|component| writeln!(out, "component: {} {} {:?}", component.key, component.name, component.purl))
    })?;
    documents.iter().zip(documents.iter().skip(1)).try_for_each(|(old, new)| {
        let changes = diff(old, new)?;
        writeln!(
            out,
            "diff: added={} removed={} changed={}",
            changes.added.len(),
            changes.removed.len(),
            changes.changed.len()
        )?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
