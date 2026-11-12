use crate::common::{FailingReader, TestResult};
use software_catalog::available::{name_ok, parse_available};
use software_catalog::error::InstalledError;
use software_catalog::limits::Limits;
use software_catalog::model::Manager;
use std::io::Cursor;


const SMALL_NAMES: usize = 2;


const SMALL_LINE: usize = 8;


#[test]
fn names_are_parsed_per_manager_and_bad_lines_counted() -> TestResult {
    let text = "tree\njq\ntree\n\nbad name\nUpper\n-oAPT\nlibjq.\n";
    let apt = parse_available(Cursor::new(text.as_bytes()), Manager::Apt, &Limits::default())?;
    let names: Vec<&str> = apt.names.iter().map(|(_, name)| name.as_str()).collect();
    assert_eq!(names, ["jq", "libjq.", "tree"]);
    assert_eq!(apt.malformed, 1 + 1 + 1);
    let dnf = parse_available(Cursor::new(b"java-17-openjdk\nbad name\n".as_slice()), Manager::Dnf, &Limits::default())?;
    assert!(dnf.names.contains(&(Manager::Dnf, "java-17-openjdk".to_string())));
    assert!(!name_ok(Manager::Winget, "a.b") && !name_ok(Manager::Msi, "a.msi"));
    Ok(())
}


#[test]
fn name_cap_counts_the_rest_at_n_and_n_plus_one() -> TestResult {
    let limits = Limits {
        max_available: SMALL_NAMES,
        ..Limits::default()
    };
    let exact = parse_available(Cursor::new(b"a\nb\nb\n".as_slice()), Manager::Apt, &limits)?;
    assert_eq!((exact.names.len(), exact.over_limit), (SMALL_NAMES, 0));
    let over = parse_available(Cursor::new(b"a\nb\nc\nd\n".as_slice()), Manager::Apt, &limits)?;
    assert_eq!((over.names.len(), over.over_limit), (SMALL_NAMES, SMALL_NAMES));
    Ok(())
}


#[test]
fn bytes_lines_and_utf8_are_bounded() -> TestResult {
    let limits = Limits {
        max_installed_bytes: SMALL_LINE,
        max_line_bytes: SMALL_LINE,
        ..Limits::default()
    };
    assert!(parse_available(Cursor::new(vec![b'a'; SMALL_LINE]), Manager::Apt, &limits).is_ok());
    assert!(matches!(
        parse_available(Cursor::new(vec![b'a'; SMALL_LINE + 1]), Manager::Apt, &limits),
        Err(InstalledError::TooLarge { limit: SMALL_LINE })
    ));
    assert!(matches!(
        parse_available(FailingReader, Manager::Apt, &limits),
        Err(InstalledError::Read(_))
    ));
    let roomy = Limits {
        max_line_bytes: SMALL_LINE,
        ..Limits::default()
    };
    let mut bytes = "a".repeat(SMALL_LINE + 1).into_bytes();
    bytes.extend_from_slice(b"\n\xff\xfe\nok\n");
    let available = parse_available(Cursor::new(bytes), Manager::Apt, &roomy)?;
    assert_eq!((available.names.len(), available.malformed), (1, SMALL_NAMES));
    Ok(())
}
