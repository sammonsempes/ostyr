use siem_ingest::reader_profile::{
    changed_statement, is_database_name, pin_clause, pins, profile_refused, read_changed_bytes, url_settings, violations, CHECK_MAX_BYTES,
    MAX_DATABASE_BYTES,
};
use std::error::Error;
use std::io::{self, Cursor, Read};


const ROWS: u64 = 7;


const PAIR: usize = 2;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const CODE_ROWS: u32 = 158;


const CODE_READONLY: u32 = 164;


const CODE_RESULT: u32 = 396;


const CODE_CONSTRAINT: u32 = 452;


const CODE_TIMEOUT: u32 = 159;


const CODE_BAD_ARGUMENTS: u32 = 36;


const CODE_AUTH: u32 = 516;


const PIN_COUNT: usize = 20;


const CLEAN_NAMES: [&str; 19] = [
    "readonly",
    "max_result_rows",
    "timeout_overflow_mode",
    "timeout_overflow_mode_leaf",
    "read_overflow_mode",
    "read_overflow_mode_leaf",
    "group_by_overflow_mode",
    "result_overflow_mode",
    "sort_overflow_mode",
    "set_overflow_mode",
    "distinct_overflow_mode",
    "join_overflow_mode",
    "transfer_overflow_mode",
    "limit",
    "offset",
    "additional_result_filter",
    "filter",
    "additional_table_filters",
    "date_time_output_format",
];


const OUTSIDE_NAMES: [&str; 4] = ["max_block_size", "load_balancing", "skip_unavailable_shards", "database"];


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::ConnectionReset))
    }
}


fn limits() -> Vec<(&'static str, String)> {
    vec![("max_execution_time", "30".to_owned()), ("max_rows_to_read", "1000".to_owned())]
}


fn clean_reply() -> String {
    CLEAN_NAMES.join("\n") + "\n"
}


#[test]
fn the_clause_names_every_pin_literally() -> Result<(), Box<dyn Error>> {
    let clause = pin_clause(&limits(), ROWS);
    assert_eq!(
        clause,
        " SETTINGS max_execution_time = 30, max_rows_to_read = 1000, max_result_rows = 7, timeout_overflow_mode = 'throw', \
         timeout_overflow_mode_leaf = 'throw', read_overflow_mode = 'throw', read_overflow_mode_leaf = 'throw', group_by_overflow_mode = 'throw', \
         result_overflow_mode = 'throw', sort_overflow_mode = 'throw', set_overflow_mode = 'throw', distinct_overflow_mode = 'throw', \
         join_overflow_mode = 'throw', transfer_overflow_mode = 'throw', limit = 0, offset = 0, additional_result_filter = '', filter = '', \
         additional_table_filters = {}, date_time_output_format = 'simple'"
    );
    assert!(!clause.contains("break"));
    assert_eq!(pins(&limits(), ROWS).len(), PIN_COUNT);
    assert_eq!(
        url_settings(None),
        vec![("readonly", "2".to_owned()), ("http_write_exception_in_output_format", "0".to_owned())]
    );
    assert_eq!(
        url_settings(Some("events")),
        vec![
            ("readonly", "2".to_owned()),
            ("http_write_exception_in_output_format", "0".to_owned()),
            ("database", "events".to_owned())
        ]
    );
    Ok(())
}


#[test]
fn the_check_statement_carries_the_full_pin_clause_with_every_reset() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        changed_statement(),
        "SELECT `name` FROM `system`.`settings` WHERE `changed` SETTINGS max_result_rows = 64, timeout_overflow_mode = 'throw', \
         timeout_overflow_mode_leaf = 'throw', read_overflow_mode = 'throw', read_overflow_mode_leaf = 'throw', group_by_overflow_mode = 'throw', \
         result_overflow_mode = 'throw', sort_overflow_mode = 'throw', set_overflow_mode = 'throw', distinct_overflow_mode = 'throw', \
         join_overflow_mode = 'throw', transfer_overflow_mode = 'throw', limit = 0, offset = 0, additional_result_filter = '', filter = '', \
         additional_table_filters = {}, date_time_output_format = 'simple' FORMAT TabSeparated"
    );
    Ok(())
}


#[test]
fn a_clean_reply_passes_and_the_exception_format_the_limits_and_the_url_database_are_allowed() -> Result<(), Box<dyn Error>> {
    assert_eq!(violations(clean_reply().as_bytes(), &limits(), None), 0);
    let with_allowed = clean_reply() + "http_write_exception_in_output_format\nmax_execution_time\nmax_rows_to_read\n";
    assert_eq!(violations(with_allowed.as_bytes(), &limits(), None), 0);
    assert_eq!(violations(with_allowed.as_bytes(), &[], None), PAIR);
    assert_eq!(violations(format!("{}database\n", clean_reply()).as_bytes(), &[], Some("events")), 0);
    assert_eq!(violations(format!("{}database\n", clean_reply()).as_bytes(), &[], None), 1);
    Ok(())
}


#[test]
fn every_name_outside_the_allowed_list_is_refused_by_name() -> Result<(), Box<dyn Error>> {
    OUTSIDE_NAMES.iter().for_each(|name| {
        let reply = format!("{}{name}\n", clean_reply());
        assert_eq!(violations(reply.as_bytes(), &limits(), None), 1, "{name}");
        assert_eq!(violations(reply.as_bytes(), &[], None), 1, "{name}");
    });
    Ok(())
}


#[test]
fn an_empty_reply_a_missing_name_and_a_big_reply_are_counted() -> Result<(), Box<dyn Error>> {
    let extra = clean_reply() + "max_block_size\nload_balancing\n";
    assert_eq!(violations(extra.as_bytes(), &limits(), None), PAIR);
    assert_eq!(violations(b"", &limits(), None), CLEAN_NAMES.len());
    CLEAN_NAMES.iter().for_each(|missing| {
        let others: Vec<&str> = CLEAN_NAMES.iter().copied().filter(|name| name != missing).collect();
        assert_eq!(violations(others.join("\n").as_bytes(), &limits(), None), 1, "{missing}");
    });
    let big = clean_reply() + &"readonly\n".repeat(CHECK_MAX_BYTES as usize);
    assert!(violations(big.as_bytes(), &limits(), None) >= 1);
    assert_eq!(violations(&NOT_UTF8, &limits(), None), CLEAN_NAMES.len() + 1);
    Ok(())
}


#[test]
fn a_database_name_is_a_plain_identifier() -> Result<(), Box<dyn Error>> {
    assert!(is_database_name("events"));
    assert!(is_database_name("_a1"));
    assert!(is_database_name(&"a".repeat(MAX_DATABASE_BYTES)));
    ["", "1a", "a-b", "a.b", "a b", "a&b=c", "\u{e9}"]
        .iter()
        .for_each(|name| assert!(!is_database_name(name), "{name}"));
    assert!(!is_database_name(&"a".repeat(MAX_DATABASE_BYTES + 1)));
    Ok(())
}


#[test]
fn the_check_reply_is_read_through_a_cap() -> Result<(), Box<dyn Error>> {
    let long = vec![b'a'; CHECK_MAX_BYTES as usize * PAIR];
    assert_eq!(read_changed_bytes(Cursor::new(long))?.len() as u64, CHECK_MAX_BYTES + 1);
    assert_eq!(read_changed_bytes(Cursor::new(b"x".to_vec()))?, b"x".to_vec());
    assert_eq!(
        read_changed_bytes(Broken).err().map(|error| error.kind()),
        Some(io::ErrorKind::ConnectionReset)
    );
    Ok(())
}


#[test]
fn profile_codes_are_rows_readonly_and_constraint() -> Result<(), Box<dyn Error>> {
    [CODE_ROWS, CODE_READONLY, CODE_RESULT, CODE_CONSTRAINT]
        .iter()
        .for_each(|code| assert!(profile_refused(Some(*code))));
    [None, Some(CODE_TIMEOUT), Some(CODE_BAD_ARGUMENTS), Some(CODE_AUTH)]
        .iter()
        .for_each(|code| assert!(!profile_refused(*code)));
    Ok(())
}
