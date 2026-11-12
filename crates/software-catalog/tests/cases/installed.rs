use crate::common::{FailingReader, TestResult};
use software_catalog::error::InstalledError;
use software_catalog::installed::parse_installed;
use software_catalog::limits::Limits;
use std::io::Cursor;


const SMALL_ROWS: usize = 2;


const SMALL_LINE: usize = 16;


#[test]
fn rows_are_parsed_and_bad_lines_counted() -> TestResult {
    let text = "curl\t8.5.0-2ubuntu10\njq\t1.7.1-3\n\nbad line\nUpper\t1.0\nnotab\nctl\t1.0\u{202e}\nx\t-1\n\u{1}\n";
    let installed = parse_installed(Cursor::new(text.as_bytes()), &Limits::default())?;
    assert_eq!(installed.rows.len(), SMALL_ROWS);
    assert_eq!(installed.malformed, SMALL_ROWS + SMALL_ROWS + SMALL_ROWS);
    assert_eq!(installed.over_limit, 0);
    assert_eq!(installed.rows.first().map(|row| row.version.as_str()), Some("8.5.0-2ubuntu10"));
    Ok(())
}


#[test]
fn row_cap_counts_the_rest_at_n_and_n_plus_one() -> TestResult {
    let limits = Limits {
        max_installed: SMALL_ROWS,
        ..Limits::default()
    };
    let exact = parse_installed(Cursor::new(b"a\t1\nb\t1\n".as_slice()), &limits)?;
    assert_eq!((exact.rows.len(), exact.over_limit), (SMALL_ROWS, 0));
    let over = parse_installed(Cursor::new(b"a\t1\nb\t1\nc\t1\nd\t1\n".as_slice()), &limits)?;
    assert_eq!((over.rows.len(), over.over_limit), (SMALL_ROWS, SMALL_ROWS));
    Ok(())
}


#[test]
fn a_huge_inventory_is_refused_by_bytes() -> TestResult {
    let limits = Limits {
        max_installed_bytes: SMALL_LINE,
        ..Limits::default()
    };
    assert!(parse_installed(Cursor::new(vec![b'a'; SMALL_LINE]), &limits).is_ok());
    assert!(matches!(
        parse_installed(Cursor::new(vec![b'a'; SMALL_LINE + 1]), &limits),
        Err(InstalledError::TooLarge { limit: SMALL_LINE })
    ));
    assert!(matches!(parse_installed(FailingReader, &limits), Err(InstalledError::Read(_))));
    Ok(())
}


#[test]
fn long_and_non_utf8_lines_are_malformed() -> TestResult {
    let limits = Limits {
        max_line_bytes: SMALL_LINE,
        ..Limits::default()
    };
    let mut bytes = format!("a\t{}\n", "1".repeat(SMALL_LINE)).into_bytes();
    bytes.extend_from_slice(b"b\t\xff\xfe\nc\t1\n");
    let installed = parse_installed(Cursor::new(bytes), &limits)?;
    assert_eq!((installed.rows.len(), installed.malformed), (1, SMALL_ROWS));
    Ok(())
}


#[test]
fn removed_packages_with_a_status_column_are_not_installed() -> TestResult {
    let text = "nano\t7.2\trc \ntree\t2.1\tii \ncurl\t8.5\nbad\t1\tii\textra ok\n";
    let installed = parse_installed(Cursor::new(text.as_bytes()), &Limits::default())?;
    assert_eq!(installed.not_installed, 1 + 1);
    assert_eq!(
        installed.rows.iter().map(|row| row.package.as_str()).collect::<Vec<_>>(),
        ["tree", "curl"]
    );
    Ok(())
}
