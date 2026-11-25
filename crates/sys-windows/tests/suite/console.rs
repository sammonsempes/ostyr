use crate::types::TestResult;
use sys_windows::console::{
    begin_close, check_input_len, check_session_label, close_on_drop, command_line, console_size, coordinates, directory_text, environment_block,
    session_environment, wide_null, CUT_MARKER, DIRECTORY_UNITS, INPUT_CHUNK_BYTES, MAX_CONSOLE_COLUMNS, MAX_CONSOLE_ROWS, MAX_DIRECTORY_CHARS,
    MAX_ERROR_DIRECTORY_CHARS, MAX_SESSION_LABEL_BYTES,
};
use sys_windows::types::{CloseState, ConsoleError, ConsoleSize};


const SYSTEM_DIRECTORY: &str = "C:\\Windows\\System32";


const WINDOWS_DIRECTORY: &str = "C:\\Windows";


const SAMPLE: u32 = 10;


const WINDOWS_TEXT: &str = "C:\\Windows";


const WINDOWS_TEXT_UNITS: u32 = 10;


const LONE_SURROGATE: u16 = 0xD800;


const LETTER_A: u16 = 97;


const LETTER_B: u16 = 98;


const WIDTH: u16 = 80;


const HEIGHT: u16 = 24;


const ACCESS_DENIED: u32 = 5;


const SOME_MILLIS: u32 = 7;


const LONG_FACTOR: usize = 4;


const MEGABYTE: usize = 1_048_576;


fn decode(block: &[u16]) -> Vec<String> {
    block.split(|unit| *unit == 0).map(String::from_utf16_lossy).collect()
}


#[test]
fn the_command_line_quotes_the_system_cmd_and_blocks_autorun() -> TestResult {
    assert_eq!(command_line(SYSTEM_DIRECTORY)?, "\"C:\\Windows\\System32\\cmd.exe\" /D");
    Ok(())
}


#[test]
fn the_command_line_refuses_a_directory_that_is_not_a_clean_drive_path() -> TestResult {
    for bad in [
        "",
        "cmd.exe",
        "C:",
        "C:Windows",
        "a\" /C calc",
        "C:\\a\"b",
        "C:\\a\0b",
        "C:\\a;b",
        "\\\\server\\share",
        "C:\\a\\..\\b",
        "C:\\a/b",
        "C:\\a\\\\b",
        "C:\\a:b",
        "C:\\a<b",
        "C:\\a.",
    ] {
        assert!(matches!(command_line(bad), Err(ConsoleError::BadDirectory(_))), "{bad}");
    }
    Ok(())
}


#[test]
fn a_size_inside_the_bounds_is_accepted() -> TestResult {
    assert_eq!(console_size(1, 1)?, ConsoleSize { columns: 1, rows: 1 });
    let largest = console_size(u32::from(MAX_CONSOLE_COLUMNS), u32::from(MAX_CONSOLE_ROWS))?;
    assert_eq!(
        largest,
        ConsoleSize {
            columns: MAX_CONSOLE_COLUMNS,
            rows: MAX_CONSOLE_ROWS
        }
    );
    Ok(())
}


#[test]
fn a_size_outside_the_bounds_is_refused() -> TestResult {
    let columns_over = u32::from(MAX_CONSOLE_COLUMNS) + 1;
    let rows_over = u32::from(MAX_CONSOLE_ROWS) + 1;
    assert!(matches!(console_size(0, SAMPLE), Err(ConsoleError::BadSize { .. })));
    assert!(matches!(console_size(SAMPLE, 0), Err(ConsoleError::BadSize { .. })));
    assert!(matches!(console_size(columns_over, SAMPLE), Err(ConsoleError::BadSize { .. })));
    assert!(matches!(console_size(SAMPLE, rows_over), Err(ConsoleError::BadSize { .. })));
    assert!(matches!(console_size(u32::MAX, SAMPLE), Err(ConsoleError::BadSize { .. })));
    assert!(matches!(console_size(SAMPLE, u32::MAX), Err(ConsoleError::BadSize { .. })));
    Ok(())
}


#[test]
fn the_block_is_sorted_case_insensitively_and_double_nul_terminated() -> TestResult {
    let block = environment_block(&[("b", "2"), ("A", "1"), ("c", "")])?;
    assert_eq!(decode(&block), vec!["A=1", "b=2", "c=", "", ""]);
    assert!(block.ends_with(&[0, 0]));
    Ok(())
}


#[test]
fn the_block_is_utf16() -> TestResult {
    let block = environment_block(&[("N", "\u{1F600}")])?;
    assert_eq!(block, "N=\u{1F600}\0\0".encode_utf16().collect::<Vec<u16>>());
    Ok(())
}


#[test]
fn an_empty_block_is_two_nuls() -> TestResult {
    assert_eq!(environment_block(&[])?, vec![0, 0]);
    Ok(())
}


#[test]
fn a_name_with_equals_nul_or_nothing_is_refused() -> TestResult {
    assert!(matches!(environment_block(&[("A=B", "x")]), Err(ConsoleError::BadEnvironmentName)));
    assert!(matches!(environment_block(&[("A\0B", "x")]), Err(ConsoleError::BadEnvironmentName)));
    assert!(matches!(environment_block(&[("", "x")]), Err(ConsoleError::BadEnvironmentName)));
    Ok(())
}


#[test]
fn a_name_outside_the_ascii_grammar_is_refused() -> TestResult {
    for bad in ["\u{e9}", "\u{c9}", "\u{ff21}", "\u{10400}", "A B", "A-B", "A;B", "A\n", "A%", "\u{212a}"] {
        assert!(matches!(environment_block(&[(bad, "x")]), Err(ConsoleError::BadEnvironmentName)), "{bad}");
    }
    assert_eq!(decode(&environment_block(&[("a_9Z", "x")])?), vec!["a_9Z=x", "", ""]);
    Ok(())
}


#[test]
fn the_sort_puts_numbers_then_letters_then_underscore() -> TestResult {
    let block = environment_block(&[("_a", "1"), ("a", "2"), ("1", "3"), ("Z", "4")])?;
    assert_eq!(decode(&block), vec!["1=3", "a=2", "Z=4", "_a=1", "", ""]);
    Ok(())
}


#[test]
fn a_value_with_nul_is_refused_by_name() -> TestResult {
    assert!(matches!(environment_block(&[("A", "x\0y")]), Err(ConsoleError::BadEnvironmentValue { name }) if name == "A"));
    Ok(())
}


#[test]
fn a_value_may_hold_equals() -> TestResult {
    assert_eq!(decode(&environment_block(&[("A", "x=y")])?), vec!["A=x=y", "", ""]);
    Ok(())
}


#[test]
fn a_name_defined_twice_in_any_case_is_refused() -> TestResult {
    assert!(matches!(
        environment_block(&[("Path", "1"), ("PATH", "2")]),
        Err(ConsoleError::DuplicateEnvironmentName { name }) if name == "PATH"
    ));
    Ok(())
}


#[test]
fn the_session_environment_is_the_exact_fixed_list() -> TestResult {
    let block = session_environment(SYSTEM_DIRECTORY, WINDOWS_DIRECTORY, "s1")?;
    let expected = vec![
        "ComSpec=C:\\Windows\\System32\\cmd.exe",
        "OSTYR_SESSION=s1",
        "PATH=C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\Wbem",
        "PATHEXT=.COM;.EXE;.BAT;.CMD",
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=C:\\Windows\\Temp",
        "TMP=C:\\Windows\\Temp",
        "windir=C:\\Windows",
        "",
        "",
    ];
    assert_eq!(decode(&block), expected);
    Ok(())
}


#[test]
fn the_session_environment_refuses_a_bad_windows_directory() -> TestResult {
    for bad in [
        "",
        "C",
        "1:\\x",
        "CC:\\x",
        "C:",
        "C:x",
        "\\\\server\\share",
        "C:\\a;b",
        "C:\\a\"",
        "C:\\a\0",
    ] {
        assert!(
            matches!(session_environment(SYSTEM_DIRECTORY, bad, "s"), Err(ConsoleError::BadDirectory(_))),
            "{bad}"
        );
    }
    Ok(())
}


#[test]
fn the_session_environment_refuses_a_bad_system_directory() -> TestResult {
    for bad in ["", "C:\\a;b", "System32", "C:\\a\"b"] {
        assert!(
            matches!(session_environment(bad, WINDOWS_DIRECTORY, "s"), Err(ConsoleError::BadDirectory(_))),
            "{bad}"
        );
    }
    Ok(())
}


#[test]
fn a_long_bad_directory_is_cut_in_the_error() -> TestResult {
    let long = "x".repeat(MAX_ERROR_DIRECTORY_CHARS * LONG_FACTOR);
    let error = command_line(&long).err().ok_or("accepted")?;
    let expected = format!("{}{}", "x".repeat(MAX_ERROR_DIRECTORY_CHARS), CUT_MARKER);
    assert!(matches!(error, ConsoleError::BadDirectory(ref shown) if *shown == expected));
    let exact = "y".repeat(MAX_ERROR_DIRECTORY_CHARS);
    let uncut = command_line(&exact).err().ok_or("accepted")?;
    assert!(matches!(uncut, ConsoleError::BadDirectory(ref shown) if *shown == exact));
    Ok(())
}


#[test]
fn a_directory_over_the_length_bound_is_refused_and_the_bound_is_accepted() -> TestResult {
    let filler = MAX_DIRECTORY_CHARS - "C:\\".len();
    let at_bound = format!("C:\\{}", "d".repeat(filler));
    command_line(&at_bound)?;
    let over = format!("{at_bound}d");
    assert!(matches!(command_line(&over), Err(ConsoleError::BadDirectory(_))));
    Ok(())
}


#[test]
fn a_session_label_inside_the_grammar_is_accepted() -> TestResult {
    for good in ["s1", "A.b_c-d", "0", &"a".repeat(MAX_SESSION_LABEL_BYTES)] {
        check_session_label(good)?;
    }
    Ok(())
}


#[test]
fn a_session_label_outside_the_grammar_is_refused() -> TestResult {
    let too_long = "a".repeat(MAX_SESSION_LABEL_BYTES + 1);
    let megabyte = "a".repeat(MEGABYTE);
    for bad in [
        "",
        "-s",
        "a\u{1b}b",
        "a\u{7}",
        "a\r\nb",
        "a\0",
        "%PATH%&calc",
        "a b",
        "a;b",
        "\u{e9}",
        too_long.as_str(),
        megabyte.as_str(),
    ] {
        assert!(matches!(check_session_label(bad), Err(ConsoleError::BadSessionLabel { .. })), "{bad:?}");
        assert!(matches!(
            session_environment(SYSTEM_DIRECTORY, WINDOWS_DIRECTORY, bad),
            Err(ConsoleError::BadSessionLabel { .. })
        ));
    }
    Ok(())
}


#[test]
fn a_console_closes_once_and_drop_after_close_does_nothing() -> TestResult {
    let mut state = CloseState::Open;
    begin_close(&mut state)?;
    assert_eq!(state, CloseState::Closed);
    assert!(matches!(begin_close(&mut state), Err(ConsoleError::AlreadyClosed)));
    assert!(!close_on_drop(&mut state));
    Ok(())
}


#[test]
fn drop_closes_an_open_console_once() -> TestResult {
    let mut state = CloseState::Open;
    assert!(close_on_drop(&mut state));
    assert!(!close_on_drop(&mut state));
    assert_eq!(state, CloseState::Closed);
    Ok(())
}


#[test]
fn an_input_write_over_the_chunk_is_refused_by_name() -> TestResult {
    check_input_len(0)?;
    check_input_len(INPUT_CHUNK_BYTES)?;
    assert!(matches!(
        check_input_len(INPUT_CHUNK_BYTES + 1),
        Err(ConsoleError::InputTooLarge { bytes, max_bytes }) if bytes == INPUT_CHUNK_BYTES + 1 && max_bytes == INPUT_CHUNK_BYTES
    ));
    Ok(())
}


#[test]
fn a_directory_text_needs_a_length_inside_the_buffer() -> TestResult {
    let mut buffer = vec![0; DIRECTORY_UNITS];
    for (slot, unit) in buffer.iter_mut().zip(WINDOWS_TEXT.encode_utf16()) {
        *slot = unit;
    }
    assert_eq!(directory_text("op", &buffer, WINDOWS_TEXT_UNITS)?, WINDOWS_TEXT);
    let last = u32::try_from(DIRECTORY_UNITS - 1)?;
    assert_eq!(directory_text("op", &buffer, last)?.len(), DIRECTORY_UNITS - 1);
    for bad in [0, u32::try_from(DIRECTORY_UNITS)?, u32::MAX] {
        assert!(
            matches!(directory_text("op", &buffer, bad), Err(ConsoleError::DirectoryRead { operation: "op" })),
            "{bad}"
        );
    }
    let lone_surrogate = [LONE_SURROGATE, 0, 0];
    assert!(matches!(
        directory_text("op", &lone_surrogate, 1),
        Err(ConsoleError::DirectoryRead { .. })
    ));
    Ok(())
}


#[test]
fn wide_text_ends_with_one_nul_and_coordinates_follow_the_size() -> TestResult {
    assert_eq!(wide_null("ab"), vec![LETTER_A, LETTER_B, 0]);
    assert_eq!(wide_null(""), vec![0]);
    assert_eq!(
        coordinates(ConsoleSize {
            columns: WIDTH,
            rows: HEIGHT
        }),
        (WIDTH.cast_signed(), HEIGHT.cast_signed())
    );
    assert_eq!(coordinates(ConsoleSize { columns: u16::MAX, rows: 1 }), (i16::MAX, 1));
    Ok(())
}


#[test]
fn the_new_errors_describe_themselves() -> TestResult {
    let texts = [
        ConsoleError::Windows {
            operation: "Op",
            code: ACCESS_DENIED,
        }
        .to_string(),
        ConsoleError::Io {
            operation: "Op",
            kind: std::io::ErrorKind::BrokenPipe,
        }
        .to_string(),
        ConsoleError::CloseTimeout { millis: SOME_MILLIS }.to_string(),
        ConsoleError::DrainFailed.to_string(),
    ];
    assert!(texts.iter().all(|text| !text.is_empty()));
    assert!(texts.iter().any(|text| text.contains("0x00000005")));
    Ok(())
}
