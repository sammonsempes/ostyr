use crate::common::{available, catalogue, entry, FailingReader, TestResult};
use software_catalog::error::InstalledError;
use software_catalog::installed_winget::parse_winget_export;
use software_catalog::limits::Limits;
use software_catalog::model::{ActionKind, Assignment, Installed, Manager, Source};
use software_catalog::plan::plan;
use std::io::Cursor;


const FIXTURE: &str = include_str!("../fixtures/winget-export.json");


const WINGET_HEAD: &str = r#""SourceDetails":{"Name":"winget","Identifier":"Microsoft.Winget.Source_8wekyb3d8bbwe"}"#;


const SMALL_COUNT: usize = 2;


const MANY_PACKAGES: usize = 100_000;


const MANY_SOURCES: usize = 10_000;


const DEEP: usize = 10_000;


const LONG_ID: usize = 300;


const MIB: usize = 1024 * 1024;


const OVER_BYTES: usize = 17 * MIB;


fn parse_with_limits(text: &str, limits: &Limits) -> Result<Installed, InstalledError> {
    parse_winget_export(Cursor::new(text.as_bytes()), limits)
}


fn parse(text: &str) -> Result<Installed, InstalledError> {
    parse_with_limits(text, &Limits::default())
}


fn winget(packages: &str) -> String {
    format!(r#"{{"Sources":[{{"Packages":[{packages}],{WINGET_HEAD}}}]}}"#)
}


fn plan_kind(installed: &Installed, pin: &str) -> Result<ActionKind, Box<dyn std::error::Error>> {
    let cat = catalogue(vec![entry("git", Source::Winget("Git.Git".to_string()), pin)]);
    let assignment = Assignment {
        install: vec!["git".to_string()],
        remove: vec![],
    };
    let result = plan(&cat, &assignment, installed, &available(Manager::Winget, &[]))?;
    Ok(result.actions.first().ok_or("no action")?.kind)
}


#[test]
fn fixture_gives_rows_and_counts_other_sources() -> TestResult {
    let installed = parse(FIXTURE)?;
    let found: Vec<(&str, &str)> = installed.rows.iter().map(|row| (row.package.as_str(), row.version.as_str())).collect();
    assert_eq!(
        found,
        vec![("7zip.7zip", "23.01"), ("Git.Git", "2.43.0"), ("Microsoft.VisualStudioCode", "")]
    );
    assert!(installed.rows.iter().all(|row| row.manager == Manager::Winget && !row.held));
    assert_eq!(
        (
            installed.other_source,
            installed.malformed,
            installed.unreadable_versions,
            installed.duplicate_ids,
            installed.over_limit
        ),
        (SMALL_COUNT, 0, 1, 0, 0)
    );
    assert_eq!(plan_kind(&installed, "2.44.0")?, ActionKind::Update);
    assert_eq!(plan_kind(&installed, "2.0.0")?, ActionKind::NewerThanCatalogue);
    Ok(())
}


#[test]
fn a_bom_prefixed_file_parses_the_same() -> TestResult {
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend_from_slice(FIXTURE.as_bytes());
    let with_bom = parse_winget_export(Cursor::new(bytes), &Limits::default())?;
    assert_eq!(with_bom, parse(FIXTURE)?);
    Ok(())
}


#[test]
fn bad_package_ids_and_shapes_are_malformed() -> TestResult {
    let long = format!(r#"{{"PackageIdentifier":"{}.x","Version":"1"}}"#, "a".repeat(LONG_ID));
    let packages = [
        r#"{"PackageIdentifier":"A\u001b.B","Version":"1"}"#,
        r#"{"PackageIdentifier":"A.\u202eB","Version":"1"}"#,
        r#"{"PackageIdentifier":"-A.B","Version":"1"}"#,
        r#"{"PackageIdentifier":"NoDot","Version":"1"}"#,
        r#"{"Version":"1"}"#,
        r#"{"PackageIdentifier":5}"#,
        r#"["A.B","1"]"#,
        r#""A.B""#,
        r#"{"PackageIdentifier":"A.B","PackageIdentifier":"C.D","Version":"1"}"#,
        long.as_str(),
    ];
    let installed = parse(&winget(&packages.join(",")))?;
    assert_eq!((installed.rows.len(), installed.malformed), (0, packages.len()));
    Ok(())
}


#[test]
fn a_refused_version_is_kept_empty_and_plans_unknown() -> TestResult {
    let long = format!(r#"{{"PackageIdentifier":"Z.Z","Version":"{}"}}"#, "1".repeat(LONG_ID));
    let packages = [
        r#"{"PackageIdentifier":"Git.Git","Version":"< 1.2.3"}"#,
        r#"{"PackageIdentifier":"B.B","Version":5}"#,
        r#"{"PackageIdentifier":"C.C","Version":null}"#,
        r#"{"PackageIdentifier":"D.D","Version":"1\u001b"}"#,
        r#"{"PackageIdentifier":"E.E","Version":""}"#,
        long.as_str(),
    ];
    let installed = parse(&winget(&packages.join(",")))?;
    assert_eq!(
        (installed.rows.len(), installed.unreadable_versions, installed.malformed),
        (packages.len(), packages.len(), 0)
    );
    assert!(installed.rows.iter().all(|row| row.version.is_empty()));
    assert_eq!(plan_kind(&installed, "2.43.0")?, ActionKind::Unknown);
    Ok(())
}


#[test]
fn a_duplicate_id_is_one_unknown_row_never_a_newer_one() -> TestResult {
    let packages = r#"{"PackageIdentifier":"Git.Git","Version":"9.0.0"},{"PackageIdentifier":"git.git","Version":"1.0.0"},{"PackageIdentifier":"A.B","Version":"1"},{"PackageIdentifier":"A.B","Version":"1"}"#;
    let installed = parse(&winget(packages))?;
    assert_eq!(installed.duplicate_ids, SMALL_COUNT);
    assert_eq!(installed.rows.len(), SMALL_COUNT + 1);
    assert!(installed.rows.iter().all(|row| row.version.is_empty()));
    assert_eq!(plan_kind(&installed, "2.43.0")?, ActionKind::Unknown);
    Ok(())
}


#[test]
fn package_cap_counts_without_decoding() -> TestResult {
    let limits = Limits {
        max_installed: SMALL_COUNT,
        ..Limits::default()
    };
    let exact = parse_with_limits(
        &winget(r#"{"PackageIdentifier":"A.B","Version":"1"},{"PackageIdentifier":"C.D","Version":"1"}"#),
        &limits,
    )?;
    assert_eq!((exact.rows.len(), exact.over_limit), (SMALL_COUNT, 0));
    let over = parse_with_limits(
        &winget(r#"{"PackageIdentifier":"A.B"},{"PackageIdentifier":"C.D"},{"PackageIdentifier":"-"}"#),
        &limits,
    )?;
    assert_eq!((over.rows.len(), over.over_limit, over.malformed), (0, SMALL_COUNT + 1, 0));
    Ok(())
}


#[test]
fn huge_inputs_are_counted_or_refused() -> TestResult {
    let element = r#"{"PackageIdentifier":"A.B","Version":"1"}"#;
    let many = winget(&vec![element; MANY_PACKAGES].join(","));
    assert_eq!(parse(&many)?.over_limit, MANY_PACKAGES);
    let sources = format!(r#"{{"Sources":[{}]}}"#, "{},".repeat(MANY_SOURCES - 1) + "{}");
    assert!(matches!(parse(&sources), Err(InstalledError::TooManySources { .. })));
    let deep = format!(
        r#"{{"Sources":[{{"Packages":[{}],{WINGET_HEAD}}}]}}"#,
        "[".repeat(DEEP) + &"]".repeat(DEEP)
    );
    assert_eq!(parse(&deep)?.malformed, 1);
    Ok(())
}


#[test]
fn source_cap_and_shapes() -> TestResult {
    let limits = Limits {
        max_sources: SMALL_COUNT,
        ..Limits::default()
    };
    let other = r#"{"Packages":[],"SourceDetails":{"Name":"x"}}"#;
    let three = format!(r#"{{"Sources":[{other},{other},{other}]}}"#);
    assert!(matches!(
        parse_with_limits(&three, &limits),
        Err(InstalledError::TooManySources { limit: SMALL_COUNT })
    ));
    let two = format!(r#"{{"Sources":[{other},{other}]}}"#);
    assert_eq!(parse_with_limits(&two, &limits)?.other_source, 0);
    let broken = [
        "5",
        r#"["a"]"#,
        r#"{"Packages":[]}"#,
        r#"{"SourceDetails":{"Name":"x"}}"#,
        r#"{"Packages":5,"SourceDetails":{"Name":"x"}}"#,
        r#"{"Packages":[],"SourceDetails":{"Name":5}}"#,
        r#"{"Packages":[],"Packages":[],"SourceDetails":{"Name":"x"}}"#,
        r#"{"Packages":[],"SourceDetails":{"Name":"x","Name":"y"}}"#,
    ];
    broken.iter().enumerate().try_for_each(|(index, source)| {
        let text = format!(r#"{{"Sources":[{other},{source}]}}"#);
        assert!(matches!(parse(&text), Err(InstalledError::WingetSource { index: 1 })), "{index}");
        Ok::<(), InstalledError>(())
    })?;
    Ok(())
}


#[test]
fn two_winget_sources_are_refused_and_a_foreign_identifier_is_another_source() -> TestResult {
    let one = format!(r#"{{"Packages":[{{"PackageIdentifier":"A.B"}}],{WINGET_HEAD}}}"#);
    let twice = format!(r#"{{"Sources":[{one},{one}]}}"#);
    assert!(matches!(parse(&twice), Err(InstalledError::DuplicateSource)));
    let foreign = r#"{"Packages":[{"PackageIdentifier":"-"}],"SourceDetails":{"Name":"winget","Identifier":"Other"}}"#;
    let noid = r#"{"Packages":[{"PackageIdentifier":"-"}],"SourceDetails":{"Name":"winget"}}"#;
    let installed = parse(&format!(r#"{{"Sources":[{foreign}]}}"#))?;
    assert_eq!((installed.rows.len(), installed.other_source, installed.malformed), (0, 1, 0));
    assert_eq!(parse(&format!(r#"{{"Sources":[{noid}]}}"#))?.other_source, 1);
    Ok(())
}


#[test]
fn json_errors_keep_no_document_text() -> TestResult {
    let marker = "SECRETMARKER";
    let documents = [
        format!(r#"{{"Sources":"{marker}"}}"#),
        format!(r#"{{"Sources":[{{"x":"{marker}"#),
        format!(r#"{{"Other":"{marker}"}}"#),
    ];
    documents.iter().try_for_each(|text| {
        let error = parse(text).err().ok_or("accepted")?;
        let chain: Vec<&dyn std::error::Error> = std::iter::successors(Some(&error as &dyn std::error::Error), |inner| inner.source()).collect();
        let shown: Vec<String> = chain.iter().map(|inner| format!("{inner} {inner:?}")).collect();
        assert!(matches!(error, InstalledError::Json { .. }));
        assert_eq!(chain.len(), 1);
        assert!(shown.iter().all(|line| !line.contains(marker)));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert!(matches!(parse("\u{ff}"), Err(InstalledError::Json { .. })));
    Ok(())
}


#[test]
fn byte_cap_and_read_failure() -> TestResult {
    assert!(matches!(
        parse_winget_export(Cursor::new(vec![b' '; OVER_BYTES]), &Limits::default()),
        Err(InstalledError::TooLarge { .. })
    ));
    assert!(matches!(
        parse_winget_export(FailingReader, &Limits::default()),
        Err(InstalledError::Read(_))
    ));
    Ok(())
}
