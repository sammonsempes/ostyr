mod common;


use common::{device, limits, skipped_count, FailingReader, TestResult};
use patch_inventory::error::{InventoryError, WingetError};
use patch_inventory::limits::{MAX_WINGET_ID_BYTES, MAX_WINGET_TABLES, MAX_WINGET_UPDATES, MIN_SEPARATOR_DASHES, SOURCE_OPEN_FAILED_EXIT};
use patch_inventory::model::{CliInventory, Limits, WingetSkip, WingetSource};
use patch_inventory::winget::{is_frame, lines_of, parse_winget_cli};


const ONE: &[u8] = include_bytes!("fixtures/winget-cli-en-one.txt");


const TWO: &[u8] = include_bytes!("fixtures/winget-cli-en-two.txt");


const UNKNOWN: &[u8] = include_bytes!("fixtures/winget-cli-en-unknown.txt");


const UNKNOWN_INCLUDED: &[u8] = include_bytes!("fixtures/winget-cli-en-unknown-included.txt");


const PINNED: &[u8] = include_bytes!("fixtures/winget-cli-en-pinned.txt");


const PINNED_INCLUDED: &[u8] = include_bytes!("fixtures/winget-cli-en-pinned-included.txt");


const LONG: &[u8] = include_bytes!("fixtures/winget-cli-en-long.txt");


const NONE: &[u8] = include_bytes!("fixtures/winget-cli-en-none.txt");


const MSSTORE: &[u8] = include_bytes!("fixtures/winget-cli-en-msstore.txt");


const FRENCH: &[u8] = include_bytes!("fixtures/winget-cli-fr-hand.txt");


const MSSTORE_EXIT: i32 = -1_978_335_229;


const NO_DASH_FILL: usize = 19;


const COUNT_TWO: usize = 2;


const COUNT_THREE: usize = 3;


const COUNT_FOUR: usize = 4;


const FOOTER_TWO: u32 = 2;


const FOOTER_FIVE: u32 = 5;


const INVALID_BYTE: u8 = 0xff;


const SPINNER_START: [u8; 7] = [0x0d, 0x20, 0x20, 0x20, 0x2d, 0x20, 0x0d];


const SMALL_LINE: usize = 64;


const SMALL_CAP: usize = 16;


const LONG_ID: usize = 200;


const HEADER: &str = "Name Id Version Available";


const GOOD_ROW: &str = "Foo Foo.Bar 1.0 2.0";


fn dashes() -> String {
    "-".repeat(MIN_SEPARATOR_DASHES)
}


fn table(rows: &[&str], footer: &str) -> String {
    format!("{HEADER}\r\n{}\r\n{}\r\n{footer}\r\n", dashes(), rows.join("\r\n"))
}


fn parse(bytes: &[u8]) -> Result<CliInventory, WingetError> {
    parse_winget_cli(&device(), bytes, 0, WingetSource::Winget, &limits())
}


fn parse_text(text: &str) -> Result<CliInventory, WingetError> {
    parse(text.as_bytes())
}


fn ids(inventory: &CliInventory) -> Vec<&str> {
    inventory.updates.iter().map(|update| update.package.as_str()).collect()
}


#[test]
fn the_live_one_update_capture_gives_one_record() -> TestResult {
    let inventory = parse(ONE)?;
    assert_eq!(ids(&inventory), ["Microsoft.Edge"]);
    let update = inventory.updates.first().ok_or("no update")?;
    assert_eq!(update.installed_version.as_deref(), Some("100.0.1.0"));
    assert_eq!(update.candidate_version, "156.0.4314.58");
    assert_eq!(update.origin.as_deref(), Some("winget"));
    assert_eq!(update.architecture, "any");
    assert!(!update.security);
    assert_eq!(update.tenant, "tenant-a");
    assert_eq!(update.device_id, "device-1");
    assert!(inventory.skipped.is_empty());
    assert_eq!(inventory.preamble_lines, 0);
    Ok(())
}


#[test]
fn a_live_capture_starts_with_the_spinner_bytes_the_frame_rule_names() -> TestResult {
    let head = ONE.get(..SPINNER_START.len()).ok_or("short capture")?;
    assert_eq!(head, SPINNER_START);
    Ok(())
}


#[test]
fn the_live_two_update_capture_gives_two_sorted_records_with_a_spaced_name() -> TestResult {
    let inventory = parse(TWO)?;
    assert_eq!(ids(&inventory), ["7zip.7zip", "Microsoft.Edge"]);
    assert_eq!(inventory.preamble_lines, 0);
    Ok(())
}


#[test]
fn the_english_unknown_version_footer_never_becomes_a_record() -> TestResult {
    let inventory = parse(UNKNOWN)?;
    assert_eq!(ids(&inventory), ["7zip.7zip", "Microsoft.Edge"]);
    assert!(inventory.skipped.is_empty());
    assert_eq!(inventory.preamble_lines, 0);
    Ok(())
}


#[test]
fn the_pins_footer_never_becomes_a_record() -> TestResult {
    let inventory = parse(PINNED)?;
    assert_eq!(ids(&inventory), ["Microsoft.Edge"]);
    assert!(inventory.skipped.is_empty());
    assert_eq!(parse(PINNED_INCLUDED)?.updates.len(), COUNT_TWO);
    Ok(())
}


#[test]
fn an_unknown_installed_version_word_is_a_counted_malformed_row_and_the_footer_still_matches() -> TestResult {
    let inventory = parse(UNKNOWN_INCLUDED)?;
    assert_eq!(ids(&inventory), ["7zip.7zip", "Microsoft.Edge"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Malformed), 1);
    Ok(())
}


#[test]
fn the_live_long_name_row_keeps_its_id_and_the_name_is_never_read() -> TestResult {
    let inventory = parse(LONG)?;
    assert_eq!(ids(&inventory), ["7zip.7zip", "Microsoft.Edge"]);
    assert!(inventory.skipped.is_empty());
    Ok(())
}


#[test]
fn the_live_nothing_to_upgrade_capture_is_an_empty_inventory() -> TestResult {
    let inventory = parse(NONE)?;
    assert!(inventory.updates.is_empty());
    assert!(inventory.skipped.is_empty());
    assert_eq!(inventory.preamble_lines, 0);
    Ok(())
}


#[test]
fn the_live_refused_source_capture_is_a_named_exit_error() -> TestResult {
    let refused = parse_winget_cli(&device(), MSSTORE, MSSTORE_EXIT, WingetSource::Msstore, &limits());
    assert!(matches!(refused, Err(WingetError::Exit { code: MSSTORE_EXIT })));
    Ok(())
}


#[test]
fn the_french_stand_in_capture_parses_without_any_word_of_the_language() -> TestResult {
    let inventory = parse(FRENCH)?;
    assert_eq!(ids(&inventory), ["7zip.7zip", "Microsoft.Edge"]);
    assert!(inventory.skipped.is_empty());
    assert_eq!(inventory.preamble_lines, 0);
    Ok(())
}


#[test]
fn the_source_open_exit_is_its_own_error_and_any_other_exit_is_named() -> TestResult {
    let opened = parse_winget_cli(&device(), ONE, SOURCE_OPEN_FAILED_EXIT, WingetSource::Winget, &limits());
    assert!(matches!(opened, Err(WingetError::SourceOpenFailed)));
    let other = parse_winget_cli(&device(), ONE, 1, WingetSource::Winget, &limits());
    assert!(matches!(other, Err(WingetError::Exit { code: 1 })));
    Ok(())
}


#[test]
fn origin_is_the_source_argument_and_never_a_row_token() -> TestResult {
    let from_msstore = parse_winget_cli(&device(), ONE, 0, WingetSource::Msstore, &limits())?;
    assert_eq!(from_msstore.updates.first().ok_or("no update")?.origin.as_deref(), Some("msstore"));
    let with_source_column = table(&["Foo Foo.Bar 1.0 2.0 msstore"], "1 upgrades available.");
    let refused = parse_text(&with_source_column)?;
    assert!(refused.updates.is_empty());
    assert_eq!(skipped_count(&refused.skipped, WingetSkip::Malformed), 1);
    Ok(())
}


#[test]
fn two_sources_are_two_results_and_one_failure_never_empties_the_other() -> TestResult {
    let good = parse_winget_cli(&device(), ONE, 0, WingetSource::Winget, &limits());
    let bad = parse_winget_cli(&device(), MSSTORE, MSSTORE_EXIT, WingetSource::Msstore, &limits());
    assert_eq!(good?.updates.len(), 1);
    assert!(bad.is_err());
    Ok(())
}


#[test]
fn an_unknown_installed_marker_joins_its_version_and_keeps_the_record_with_no_installed_version() -> TestResult {
    let inventory = parse_text(&table(&["Foo Foo.Bar < 1.0 2.0", "Baz Baz.Qux > 3.0 4.0"], "2 upgrades available."))?;
    assert_eq!(ids(&inventory), ["Baz.Qux", "Foo.Bar"]);
    assert!(inventory.updates.iter().all(|update| update.installed_version.is_none()));
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::UnknownInstalledVersion), COUNT_TWO);
    Ok(())
}


#[test]
fn a_marker_row_without_a_name_is_malformed() -> TestResult {
    let inventory = parse_text(&table(&["Foo.Bar < 1.0 2.0", GOOD_ROW], "2 upgrades available."))?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Malformed), 1);
    Ok(())
}


#[test]
fn a_version_token_without_a_digit_is_malformed() -> TestResult {
    let inventory = parse_text(&table(&["Foo Foo.Bar winget them.", GOOD_ROW], "2 upgrades available."))?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Malformed), 1);
    Ok(())
}


#[test]
fn a_footer_count_that_differs_from_the_rows_is_a_named_error() -> TestResult {
    let result = parse_text(&table(&[GOOD_ROW], "2 upgrades available."));
    assert!(matches!(result, Err(WingetError::FooterMismatch { footer: FOOTER_TWO, rows: 1 })));
    Ok(())
}


#[test]
fn skipped_rows_count_for_the_footer_check() -> TestResult {
    let truncated = "Foo Foo.Bar\u{2026} 1.0 2.0";
    let inventory = parse_text(&table(&[GOOD_ROW, truncated], "2 upgrades available."))?;
    assert_eq!(inventory.updates.len(), 1);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Truncated), 1);
    Ok(())
}


#[test]
fn a_footer_number_over_thirty_two_bits_is_a_named_error() -> TestResult {
    let result = parse_text(&table(&[GOOD_ROW], "99999999999 upgrades available."));
    assert!(matches!(result, Err(WingetError::FooterTooLarge)));
    Ok(())
}


#[test]
fn a_table_ending_in_a_line_with_no_number_is_a_named_error() -> TestResult {
    let at_the_end = parse_text(&table(&[GOOD_ROW], "no number here at all"));
    assert!(matches!(at_the_end, Err(WingetError::FooterUnreadable)));
    let before_a_blank = parse_text(&format!("{}\r\n", table(&[GOOD_ROW], "no number here at all")));
    assert!(matches!(before_a_blank, Err(WingetError::FooterUnreadable)));
    let several = parse_text(&table(&[GOOD_ROW], "1 of 2 upgrades available."));
    assert!(matches!(several, Err(WingetError::FooterUnreadable)));
    Ok(())
}


#[test]
fn a_table_with_no_footer_at_the_end_of_input_is_read_without_a_count() -> TestResult {
    let inventory = parse_text(&format!("{HEADER}\r\n{}\r\n{GOOD_ROW}\r\n", dashes()))?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    Ok(())
}


#[test]
fn a_malformed_line_before_the_footer_is_skipped_and_never_ends_the_table() -> TestResult {
    let inventory = parse_text(&table(&["not a row", GOOD_ROW, "Baz Baz.Qux 3.0 4.0"], "3 upgrades available."))?;
    assert_eq!(ids(&inventory), ["Baz.Qux", "Foo.Bar"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Malformed), 1);
    Ok(())
}


#[test]
fn a_short_line_inside_the_table_does_not_end_it() -> TestResult {
    let inventory = parse_text(&table(&["x y", "Baz Baz.Qux 3.0 4.0"], "2 upgrades available."))?;
    assert_eq!(ids(&inventory), ["Baz.Qux"]);
    Ok(())
}


#[test]
fn a_blank_line_ends_the_table_and_what_follows_is_not_read_as_rows() -> TestResult {
    let inventory = parse_text(&format!("{}\r\nBaz Baz.Qux 3.0 4.0\r\n", table(&[GOOD_ROW], "1 upgrades available.")))?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    Ok(())
}


#[test]
fn a_dash_line_of_nineteen_is_not_a_separator() -> TestResult {
    let result = parse_text(&format!(
        "{HEADER}\r\n{}\r\n{GOOD_ROW}\r\n1 upgrades available.\r\n",
        "-".repeat(NO_DASH_FILL)
    ));
    assert!(matches!(result, Err(WingetError::UnrecognisedLayout)));
    Ok(())
}


#[test]
fn a_dash_line_at_the_start_or_after_a_blank_or_a_frame_is_not_a_separator() -> TestResult {
    let first = parse_text(&format!("{}\r\n{GOOD_ROW}\r\n", dashes()));
    assert!(matches!(first, Err(WingetError::UnrecognisedLayout)));
    let after_blank = parse_text(&format!("{HEADER}\r\n\r\n{}\r\n{GOOD_ROW}\r\n", dashes()));
    assert!(matches!(after_blank, Err(WingetError::UnrecognisedLayout)));
    let after_frame = parse_text(&format!("   - \r\n{}\r\n{GOOD_ROW}\r\n", dashes()));
    assert!(matches!(after_frame, Err(WingetError::UnrecognisedLayout)));
    Ok(())
}


#[test]
fn a_dash_line_with_another_character_is_not_a_separator() -> TestResult {
    let result = parse_text(&format!("{HEADER}\r\n{}x\r\n{GOOD_ROW}\r\n", dashes()));
    assert!(matches!(result, Err(WingetError::UnrecognisedLayout)));
    Ok(())
}


#[test]
fn a_lone_spinner_dash_is_never_a_separator() -> TestResult {
    let result = parse_text("Name\r\n   - \r\n-\r\n");
    assert!(matches!(result, Err(WingetError::UnrecognisedLayout)));
    Ok(())
}


#[test]
fn a_carriage_return_progress_region_is_split_into_lines() -> TestResult {
    let lines: Vec<&str> = lines_of("a\rb\r\nc\n\nd").collect();
    assert_eq!(lines, ["a", "b", "c", "", "d"]);
    assert_eq!(lines_of("").count(), 0);
    let region = "   - \r   \\ \r".repeat(MAX_WINGET_UPDATES);
    let tight = Limits {
        max_bytes: limits().max_bytes,
        max_lines: limits().max_lines,
        max_line_bytes: SMALL_LINE,
    };
    let inventory = parse_winget_cli(
        &device(),
        format!("{region}{}", table(&[GOOD_ROW], "1 upgrades available.")).as_bytes(),
        0,
        WingetSource::Winget,
        &tight,
    )?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    assert_eq!(inventory.preamble_lines, 0);
    Ok(())
}


#[test]
fn frames_are_recognised_by_their_exact_forms_only() -> TestResult {
    assert!(is_frame("   - "));
    assert!(is_frame("   \\ "));
    assert!(is_frame("   | "));
    assert!(is_frame("   / "));
    assert!(!is_frame("   -"));
    assert!(!is_frame("   x "));
    assert!(!is_frame("  - "));
    assert!(is_frame("  \u{2588}\u{2592}\u{2592}  45.4 MB / 45.4 MB"));
    assert!(is_frame("  \u{2588}\u{2588}"));
    assert!(!is_frame("  45.4 MB"));
    assert!(!is_frame("\u{2588}\u{2592}  1 MB"));
    assert!(!is_frame("  \u{2588}\u{2592}  1 MB \u{00e9}"));
    Ok(())
}


#[test]
fn a_progress_row_after_the_separator_is_a_counted_malformed_row_not_a_stripped_frame() -> TestResult {
    let inventory = parse_text(&table(&["  \u{2588}\u{2592}  1 MB / 2 MB", GOOD_ROW], "2 upgrades available."))?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Malformed), 1);
    Ok(())
}


#[test]
fn preamble_lines_before_the_header_are_counted_and_frames_are_not() -> TestResult {
    let text = format!(
        "   - \r\nFailed in attempting to update the source: winget\r\n  \u{2588}\u{2592}  1 MB / 2 MB\r\n\r\n{}",
        table(&[GOOD_ROW], "1 upgrades available.")
    );
    let inventory = parse_text(&text)?;
    assert_eq!(inventory.preamble_lines, 1);
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    Ok(())
}


#[test]
fn a_second_table_is_read_with_its_own_footer_and_the_explicit_targeting_line_is_not_a_record() -> TestResult {
    let second = format!(
        "\r\nThe following packages have an upgrade available, but require explicit targeting for upgrade:\r\n{HEADER}\r\n{}\r\nBaz Baz.Qux 3.0 4.0\r\n1 upgrades available.\r\n",
        dashes()
    );
    let inventory = parse_text(&format!("{}{second}", table(&[GOOD_ROW], "1 upgrades available.")))?;
    assert_eq!(ids(&inventory), ["Baz.Qux", "Foo.Bar"]);
    assert!(inventory.skipped.is_empty());
    let mismatch = parse_text(&format!(
        "{}{}",
        table(&[GOOD_ROW], "1 upgrades available."),
        second.replace("1 upgrades", "5 upgrades")
    ));
    assert!(matches!(
        mismatch,
        Err(WingetError::FooterMismatch {
            footer: FOOTER_FIVE,
            rows: 1
        })
    ));
    Ok(())
}


#[test]
fn consecutive_separators_make_an_empty_table_each() -> TestResult {
    let result = parse_text(&format!("{HEADER}\r\n{}\r\n{}\r\n{GOOD_ROW}\r\n", dashes(), dashes()));
    assert_eq!(ids(&result?), ["Foo.Bar"]);
    Ok(())
}


#[test]
fn a_third_table_is_a_named_error() -> TestResult {
    let block = table(&[GOOD_ROW], "1 upgrades available.");
    let result = parse_text(&format!("{block}\r\n{block}\r\n{block}"));
    assert!(matches!(result, Err(WingetError::TooManyTables { limit: MAX_WINGET_TABLES })));
    Ok(())
}


#[test]
fn a_non_utf8_byte_is_a_whole_input_error() -> TestResult {
    let mut bytes = table(&[GOOD_ROW], "1 upgrades available.").into_bytes();
    bytes.push(INVALID_BYTE);
    assert!(matches!(parse(&bytes), Err(WingetError::Encoding)));
    Ok(())
}


#[test]
fn a_row_over_the_line_cap_is_skipped_counted_and_still_a_row_for_the_footer() -> TestResult {
    let tight = Limits {
        max_bytes: limits().max_bytes,
        max_lines: limits().max_lines,
        max_line_bytes: SMALL_LINE,
    };
    let giant = format!("Foo {} 1.0 2.0", "A".repeat(LONG_ID));
    let text = table(&[GOOD_ROW, &giant], "2 upgrades available.");
    let inventory = parse_winget_cli(&device(), text.as_bytes(), 0, WingetSource::Winget, &tight)?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::LineTooLong), 1);
    Ok(())
}


#[test]
fn an_id_or_version_over_the_byte_cap_is_malformed() -> TestResult {
    let long_id = format!("Foo {} 1.0 2.0", "A".repeat(MAX_WINGET_ID_BYTES + 1));
    let long_version = format!("Foo Foo.Baz 1.{} 2.0", "0".repeat(MAX_WINGET_ID_BYTES));
    let inventory = parse_text(&table(&[GOOD_ROW, &long_id, &long_version], "3 upgrades available."))?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Malformed), COUNT_TWO);
    Ok(())
}


#[test]
fn an_id_or_a_version_holding_an_ellipsis_is_truncated() -> TestResult {
    let id = "Foo Foo.Ba\u{2026} 1.0 2.0";
    let installed = "Foo Foo.Bar 1.\u{2026} 2.0";
    let available = "Foo Foo.Bar 1.0 2.\u{2026}";
    let inventory = parse_text(&table(&[GOOD_ROW, id, installed, available], "4 upgrades available."))?;
    assert_eq!(inventory.updates.len(), 1);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Truncated), COUNT_THREE);
    Ok(())
}


#[test]
fn a_control_character_in_a_row_is_counted_and_never_read() -> TestResult {
    let inventory = parse_text(&table(
        &[
            GOOD_ROW,
            "Foo\u{1b} Foo.Baz 1.0 2.0",
            "Foo\tFoo.Baz 1.0 2.0",
            "Foo\u{200b} Foo.Baz 1.0 2.0",
        ],
        "4 upgrades available.",
    ))?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::ControlCharacters), COUNT_THREE);
    Ok(())
}


#[test]
fn a_row_with_a_leading_dash_or_a_bad_character_is_malformed() -> TestResult {
    let rows = [
        "Foo -Foo.Bar 1.0 2.0",
        "Foo Foo;Bar 1.0 2.0",
        "Foo Foo.Bar -1.0 2.0",
        "Foo Foo.Bar 1.0 2.0$",
        GOOD_ROW,
    ];
    let inventory = parse_text(&table(&rows, "5 upgrades available."))?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Malformed), COUNT_FOUR);
    Ok(())
}


#[test]
fn a_duplicate_id_in_any_case_keeps_the_first_and_is_counted() -> TestResult {
    let inventory = parse_text(&table(&[GOOD_ROW, "Other foo.bar 5.0 6.0"], "2 upgrades available."))?;
    assert_eq!(ids(&inventory), ["Foo.Bar"]);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Duplicate), 1);
    Ok(())
}


#[test]
fn more_rows_than_the_cap_is_a_named_error_counted_before_any_record() -> TestResult {
    let rows: Vec<String> = (0..=MAX_WINGET_UPDATES)
        .map(|number| format!("N{number} Pkg.P{number} 1.0 2.0"))
        .collect();
    let borrowed: Vec<&str> = rows.iter().map(String::as_str).collect();
    let footer = format!("{} upgrades available.", rows.len());
    let result = parse_text(&table(&borrowed, &footer));
    assert!(matches!(result, Err(WingetError::TooManyUpdates { limit: MAX_WINGET_UPDATES })));
    Ok(())
}


#[test]
fn exactly_the_cap_of_rows_is_accepted() -> TestResult {
    let rows: Vec<String> = (0..MAX_WINGET_UPDATES).map(|number| format!("N{number} Pkg.P{number} 1.0 2.0")).collect();
    let borrowed: Vec<&str> = rows.iter().map(String::as_str).collect();
    let footer = format!("{} upgrades available.", rows.len());
    assert_eq!(parse_text(&table(&borrowed, &footer))?.updates.len(), MAX_WINGET_UPDATES);
    Ok(())
}


#[test]
fn nothing_but_one_line_is_an_empty_listing_and_anything_else_without_a_table_is_unrecognised() -> TestResult {
    assert!(parse_text("No installed package found matching input criteria.\r\n")?.updates.is_empty());
    assert!(matches!(parse_text(""), Err(WingetError::UnrecognisedLayout)));
    assert!(matches!(parse_text("   - \r\n  \r\n"), Err(WingetError::UnrecognisedLayout)));
    assert!(matches!(parse_text("one line\r\nsecond line\r\n"), Err(WingetError::UnrecognisedLayout)));
    Ok(())
}


#[test]
fn the_byte_and_line_caps_and_a_failing_reader_are_named_errors() -> TestResult {
    let small = Limits {
        max_bytes: SMALL_CAP,
        max_lines: limits().max_lines,
        max_line_bytes: limits().max_line_bytes,
    };
    let too_large = parse_winget_cli(&device(), ONE, 0, WingetSource::Winget, &small);
    assert!(matches!(
        too_large,
        Err(WingetError::Input(InventoryError::TooLarge { limit: SMALL_CAP }))
    ));
    let few_lines = Limits {
        max_bytes: limits().max_bytes,
        max_lines: SMALL_CAP,
        max_line_bytes: limits().max_line_bytes,
    };
    let too_many = parse_winget_cli(&device(), ONE, 0, WingetSource::Winget, &few_lines);
    assert!(matches!(
        too_many,
        Err(WingetError::Input(InventoryError::TooManyLines { limit: SMALL_CAP }))
    ));
    let failing = parse_winget_cli(&device(), FailingReader, 0, WingetSource::Winget, &limits());
    assert!(matches!(failing, Err(WingetError::Input(InventoryError::Read(_)))));
    Ok(())
}


#[test]
fn errors_carry_no_line_text() -> TestResult {
    let result = parse_text(&table(&["Marker Marker.Id 1.0 2.0"], "9 upgrades available."));
    let error = result.err().ok_or("no error")?;
    assert!(!format!("{error} {error:?}").contains("Marker"));
    Ok(())
}
