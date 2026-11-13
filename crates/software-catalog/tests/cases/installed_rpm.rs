use crate::common::{available, catalogue, entry, row, FailingReader, TestResult};
use software_catalog::error::InstalledError;
use software_catalog::installed_rpm::parse_rpm_installed;
use software_catalog::limits::Limits;
use software_catalog::model::{ActionKind, Assignment, Installed, Manager, Source};
use software_catalog::plan::plan;
use std::io::Cursor;


const SMALL_ROWS: usize = 2;


const SMALL_LINE: usize = 16;


const LAB_CAPTURE: &str = include_str!("../fixtures/lab-rpm-qa.txt");


const OVER_ROWS: usize = 50_001;


const MALFORMED_LINES: usize = 9;


const MIB: usize = 1024 * 1024;


const LONG_NAME: usize = 600;


const OVER_BYTES: usize = 17 * MIB;


fn parse(text: &str) -> Result<Installed, InstalledError> {
    parse_rpm_installed(Cursor::new(text.as_bytes()), &Limits::default())
}


fn assign(name: &str) -> Assignment {
    Assignment {
        install: vec![name.to_string()],
        remove: vec![],
    }
}


#[test]
fn rows_are_dnf_rows_and_bad_lines_counted() -> TestResult {
    let text = "curl\t0:7.76.1-26.el9\tx86_64\n\n-bad\t0:1-1\tx86_64\nsp ace\t0:1-1\tx86_64\ntab\t0:1\t2-1\tx86_64\n\
                neg\t-1:1-1\tx86_64\ncolons\t1:2:3-1\tx86_64\nunknown\t0:1-1\tmips99\nctl\t0:1-1\u{202e}\tx86_64\nshort\t0:1-1\nnorel\t0:1\tx86_64\n";
    let installed = parse(text)?;
    assert_eq!(installed.rows.len(), 1);
    assert_eq!(installed.malformed, MALFORMED_LINES);
    let found = installed.rows.first().ok_or("no row")?;
    assert_eq!(found.manager, Manager::Dnf);
    assert_eq!(
        (found.package.as_str(), found.version.as_str(), found.held),
        ("curl", "0:7.76.1-26.el9", false)
    );
    Ok(())
}


#[test]
fn long_and_non_utf8_lines_are_malformed() -> TestResult {
    let limits = Limits {
        max_line_bytes: SMALL_LINE,
        ..Limits::default()
    };
    let bytes = b"a\t0:1-1\tnoarch\nabcdefg\t0:1-1\tnoarch\n\xff\t0:1-1\tnoarch\n";
    let installed = parse_rpm_installed(Cursor::new(bytes.as_slice()), &limits)?;
    assert_eq!((installed.rows.len(), installed.malformed), (1, SMALL_ROWS));
    let long = format!("{}\t0:1-1\tx86_64\n", "a".repeat(LONG_NAME));
    assert_eq!(parse(&long)?.malformed, 1);
    Ok(())
}


#[test]
fn multilib_keeps_both_rows_and_gpg_keys_are_not_rows() -> TestResult {
    let installed = parse("glibc\t0:2.34-1.el9\tx86_64\nglibc\t0:2.34-1.el9\ti686\ngpg-pubkey\t0:fd431d51-4ae0493b\t(none)\n")?;
    assert_eq!(installed.rows.len(), SMALL_ROWS);
    assert_eq!((installed.not_installed, installed.malformed), (1, 0));
    assert_eq!(parse("gpg-pubkey\t0:fd 431\t(none)\n")?.malformed, 1);
    let cat = catalogue(vec![entry("glibc", Source::Dnf("glibc".to_string()), "2.35-1.el9")]);
    let result = plan(&cat, &assign("glibc"), &installed, &available(Manager::Dnf, &["glibc"]))?;
    assert_eq!(result.actions.iter().filter(|action| action.kind == ActionKind::Update).count(), 1);
    Ok(())
}


#[test]
fn a_forged_apt_row_never_matches_a_dnf_entry() -> TestResult {
    let installed = Installed {
        rows: vec![row(Manager::Apt, "jq", "1.0-1")],
        ..Installed::default()
    };
    let cat = catalogue(vec![entry("jq", Source::Dnf("jq".to_string()), "1.1-1")]);
    let result = plan(&cat, &assign("jq"), &installed, &available(Manager::Dnf, &["jq"]))?;
    assert_eq!(result.actions.iter().filter(|action| action.kind == ActionKind::Install).count(), 1);
    Ok(())
}


#[test]
fn row_cap_and_byte_cap() -> TestResult {
    let many = "a\t0:1-1\tnoarch\n".repeat(OVER_ROWS);
    let installed = parse(&many)?;
    assert_eq!((installed.rows.len(), installed.over_limit), (OVER_ROWS - 1, 1));
    assert!(matches!(
        parse_rpm_installed(Cursor::new(vec![b'a'; OVER_BYTES]), &Limits::default()),
        Err(InstalledError::TooLarge { .. })
    ));
    assert!(matches!(
        parse_rpm_installed(FailingReader, &Limits::default()),
        Err(InstalledError::Read(_))
    ));
    Ok(())
}


#[test]
fn the_lab_capture_parses_with_no_malformed_line() -> TestResult {
    let installed = parse(LAB_CAPTURE)?;
    assert_eq!(installed.malformed, 0);
    assert!(installed.not_installed >= 1);
    assert_eq!(installed.rows.iter().filter(|found| found.package == "glibc").count(), SMALL_ROWS);
    assert!(installed.rows.iter().any(|found| found.version.starts_with("1:")));
    assert!(installed.rows.iter().all(|found| found.version.contains(':')));
    Ok(())
}
