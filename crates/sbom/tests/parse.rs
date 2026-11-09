#[path = "common/types.rs"]
mod types;


use sbom::error::SbomError;
use sbom::model::{Limits, Sbom};
use sbom::parse::parse_cyclonedx;
use std::io::{Cursor, Read};
use types::TestResult;


const FIXTURE: &str = include_str!("fixtures/syft-debian.cdx.json");


const TENANT: &str = "tenant-a";


const ARTEFACT: &str = "web:1.0";


const FIXTURE_COMPONENTS: usize = 7;


const TWO_UNMAPPED: usize = 2;


const FOUR: usize = 4;


const SMALL_COMPONENTS: usize = 10;


const SMALL_STRING: usize = 8;


const DEPTH_TWO: usize = 2;


const DEPTH_THREE: usize = 3;


const PAST_JSON_NESTING: usize = 300;


const SMALL_BYTES: usize = 64;


const ENDLESS_PATTERN: [u8; 3] = *b"{},";


struct Endless {
    offset: usize,
}


impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut filled = 0;
        buf.iter_mut()
            .zip(ENDLESS_PATTERN.iter().cycle().skip(self.offset))
            .for_each(|(slot, byte)| {
                *slot = *byte;
                filled += 1;
            });
        self.offset = (self.offset + filled) % ENDLESS_PATTERN.len();
        Ok(filled)
    }
}


fn parse(text: &str, limits: &Limits) -> Result<Sbom, SbomError> {
    parse_cyclonedx(Cursor::new(text.as_bytes().to_vec()), TENANT, ARTEFACT, limits)
}


fn parse_default(text: &str) -> Result<Sbom, SbomError> {
    parse(text, &Limits::default())
}


#[test]
fn syft_sample_is_read() -> TestResult {
    let sbom = parse_default(FIXTURE)?;
    assert_eq!(sbom.components.len(), FIXTURE_COMPONENTS);
    assert_eq!((sbom.tenant.as_str(), sbom.artefact.as_str()), (TENANT, ARTEFACT));
    let libc = sbom
        .components
        .iter()
        .find(|component| component.name == "libc6")
        .ok_or("libc6 missing")?;
    assert_eq!(libc.version.as_deref(), Some("2.36-9+deb12u4"));
    assert_eq!(libc.kind, "library");
    assert_eq!(libc.key, "deb/debian/libc6");
    assert_eq!(libc.package.as_ref().map(|package| package.name.as_str()), Some("glibc"));
    assert_eq!(libc.package.as_ref().map(|package| package.ecosystem.as_str()), Some("Debian:12"));
    assert_eq!((sbom.skipped, sbom.bad_purls, sbom.unmapped), (0, 0, TWO_UNMAPPED));
    Ok(())
}


#[test]
fn too_many_components_with_small_cap() -> TestResult {
    let limits = Limits {
        max_components: 1,
        ..Limits::default()
    };
    let error = parse(r#"{"components":[{"name":"a"},{"name":"b"}]}"#, &limits).err().ok_or("no error")?;
    assert!(matches!(error, SbomError::TooMany { max: 1 }));
    let within = parse(r#"{"components":[{"name":"a"}]}"#, &limits)?;
    assert_eq!(within.components.len(), 1);
    Ok(())
}


#[test]
fn endless_array_stops_at_the_cap() -> TestResult {
    let limits = Limits {
        max_components: SMALL_COMPONENTS,
        ..Limits::default()
    };
    let reader = Cursor::new(br#"{"components":["#.to_vec()).chain(Endless { offset: 0 });
    let error = parse_cyclonedx(reader, TENANT, ARTEFACT, &limits).err().ok_or("no error")?;
    assert!(matches!(error, SbomError::TooMany { max: SMALL_COMPONENTS }));
    Ok(())
}


#[test]
fn oversized_document_is_refused() -> TestResult {
    let limits = Limits {
        max_bytes: SMALL_BYTES,
        ..Limits::default()
    };
    let error = parse(FIXTURE, &limits).err().ok_or("no error")?;
    assert!(matches!(error, SbomError::TooLarge { max: SMALL_BYTES }));
    let exact = r#"{"components":[]}"#;
    let limits_exact = Limits {
        max_bytes: exact.len(),
        ..Limits::default()
    };
    assert!(parse(exact, &limits_exact)?.components.is_empty());
    Ok(())
}


#[test]
fn nesting_is_flattened_up_to_the_depth_cap() -> TestResult {
    let text = r#"{"components":[{"name":"a","components":[{"name":"b","components":[{"name":"c"}]}]}]}"#;
    let allowed = Limits {
        max_depth: DEPTH_THREE,
        ..Limits::default()
    };
    let names: Vec<String> = parse(text, &allowed)?.components.into_iter().map(|component| component.name).collect();
    assert_eq!(names, ["c", "b", "a"]);
    let refused = Limits {
        max_depth: DEPTH_TWO,
        ..Limits::default()
    };
    let error = parse(text, &refused).err().ok_or("no error")?;
    assert!(matches!(error, SbomError::TooDeep { max: DEPTH_TWO }));
    Ok(())
}


#[test]
fn json_nesting_past_the_fixed_cap_is_refused() -> TestResult {
    let text = format!(r#"{{"other":{}}}"#, "[".repeat(PAST_JSON_NESTING));
    let error = parse_default(&text).err().ok_or("no error")?;
    assert!(matches!(error, SbomError::Json(_)));
    Ok(())
}


#[test]
fn malformed_components_are_counted_and_skipped() -> TestResult {
    let text = r#"{"components":[1,"x",{"version":"1"},{"name":5},{"name":"ok","version":"1","type":"library"}]}"#;
    let sbom = parse_default(text)?;
    assert_eq!(sbom.components.len(), 1);
    assert_eq!(sbom.skipped, FOUR);
    Ok(())
}


#[test]
fn long_strings_make_the_component_skipped() -> TestResult {
    let limits = Limits {
        max_string_bytes: SMALL_STRING,
        ..Limits::default()
    };
    let text = r#"{"components":[{"name":"a-much-too-long-name"},{"name":"ok","version":"0123456789"},{"name":"fine","type":"library"}]}"#;
    let sbom = parse(text, &limits)?;
    assert_eq!(sbom.components.len(), 1);
    assert_eq!(sbom.skipped, DEPTH_TWO);
    Ok(())
}


#[test]
fn bad_purl_and_unmapped_type_are_counted() -> TestResult {
    let text = r#"{"components":[
        {"name":"a","version":"1","purl":"not a purl"},
        {"name":"b","version":"1","purl":"pkg:golang/example.test/b@1"},
        {"name":"c","version":"1"},
        {"name":"d","version":"1","purl":"pkg:cargo/d@1"}]}"#;
    let sbom = parse_default(text)?;
    assert_eq!((sbom.bad_purls, sbom.unmapped, sbom.skipped), (1, TWO_UNMAPPED, 0));
    assert_eq!(sbom.components.len(), FOUR);
    assert_eq!(sbom.components.iter().filter(|component| component.package.is_some()).count(), 1);
    let first = sbom.components.first().ok_or("empty")?;
    assert_eq!((first.kind.as_str(), first.key.as_str()), ("unknown", "component/a"));
    Ok(())
}


#[test]
fn unexpected_members_are_skipped() -> TestResult {
    let text = r#"{"bomFormat":"CycloneDX","components":5,"metadata":{"components":[{"name":"x"}]}}"#;
    assert!(parse_default(text)?.components.is_empty());
    let inner = r#"{"components":[{"name":"a","components":7,"version":3,"properties":[{"name":"x"}]}]}"#;
    assert_eq!(parse_default(inner)?.components.len(), 1);
    Ok(())
}


#[test]
fn invalid_json_is_an_error_with_its_cause() -> TestResult {
    let truncated = parse_default(r#"{"components":[{"name":"a""#).err().ok_or("no error")?;
    assert!(std::error::Error::source(&truncated).is_some());
    assert!(parse_default("[]").is_err());
    assert!(parse_default(r#"{"components":[]} trailing"#).is_err());
    Ok(())
}
