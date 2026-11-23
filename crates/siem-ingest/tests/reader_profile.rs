use siem_ingest::reader_profile::{
    changed_statement, check_pins, pin_clause, pins, profile_refused, read_changed_bytes, url_settings, violations, CHECK_MAX_BYTES,
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


const CLEAN_NAMES: [&str; 3] = ["max_result_rows", "result_overflow_mode", "readonly"];


const REFUSED_PROFILE_NAMES: [&str; 16] = [
    "timeout_overflow_mode",
    "timeout_overflow_mode_leaf",
    "read_overflow_mode",
    "read_overflow_mode_leaf",
    "group_by_overflow_mode",
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
        url_settings(),
        vec![("readonly", "2".to_owned()), ("http_write_exception_in_output_format", "0".to_owned())]
    );
    Ok(())
}


#[test]
fn the_check_statement_pins_only_its_row_cap_and_the_result_overflow_mode() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        changed_statement(),
        "SELECT `name` FROM `system`.`settings` WHERE `changed` SETTINGS max_result_rows = 64, result_overflow_mode = 'throw' FORMAT TabSeparated"
    );
    assert_eq!(
        check_pins(),
        vec![("max_result_rows", "64".to_owned()), ("result_overflow_mode", "'throw'".to_owned())]
    );
    Ok(())
}


#[test]
fn a_clean_reply_passes_and_the_exception_format_and_the_limits_are_allowed() -> Result<(), Box<dyn Error>> {
    assert_eq!(violations(clean_reply().as_bytes(), &limits()), 0);
    let with_allowed = clean_reply() + "http_write_exception_in_output_format\nmax_execution_time\nmax_rows_to_read\ndatabase\n";
    assert_eq!(violations(with_allowed.as_bytes(), &limits()), 0);
    assert_eq!(violations(with_allowed.as_bytes(), &[]), PAIR);
    assert_eq!(violations(format!("{}database\n", clean_reply()).as_bytes(), &[]), 0);
    Ok(())
}


#[test]
fn every_pinned_name_a_profile_could_set_is_refused_by_name() -> Result<(), Box<dyn Error>> {
    REFUSED_PROFILE_NAMES.iter().for_each(|name| {
        let reply = format!("{}{name}\n", clean_reply());
        assert_eq!(violations(reply.as_bytes(), &limits()), 1, "{name}");
        assert_eq!(violations(reply.as_bytes(), &[]), 1, "{name}");
    });
    Ok(())
}


#[test]
fn an_unknown_name_an_empty_reply_a_missing_name_and_a_big_reply_are_counted() -> Result<(), Box<dyn Error>> {
    let extra = clean_reply() + "max_block_size\nload_balancing\n";
    assert_eq!(violations(extra.as_bytes(), &limits()), PAIR);
    assert_eq!(violations(b"", &limits()), CLEAN_NAMES.len());
    CLEAN_NAMES.iter().for_each(|missing| {
        let others: Vec<&str> = CLEAN_NAMES.iter().copied().filter(|name| name != missing).collect();
        assert_eq!(violations(others.join("\n").as_bytes(), &limits()), 1, "{missing}");
    });
    let big = clean_reply() + &"readonly\n".repeat(CHECK_MAX_BYTES as usize);
    assert!(violations(big.as_bytes(), &limits()) >= 1);
    assert_eq!(violations(&NOT_UTF8, &limits()), CLEAN_NAMES.len() + 1);
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
