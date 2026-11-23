#[path = "common/types.rs"]
mod types;


use agent_windows::created::{created_args, parse_created};
use agent_windows::cursor::{is_time_text, parse_cursor, parse_record_id, read_cursor, write_cursor};
use agent_windows::cut::{cut_data_values, cut_value};
use agent_windows::lines::{forged_line, gap_line, refused_line};
use agent_windows::model::{
    CursorState, GapReason, Item, ItemKind, Refusal, Stream, SystemInfo, DATA_CUT_BYTES, MAX_CURSOR_BYTES, MAX_ITEM_BYTES, MAX_SYSTEM_BYTES,
    REPLACEMENT, SECURITY, WORKING_DIRECTORY,
};
use agent_windows::stream::{feed_bytes, flawed, partial_item};
use agent_windows::system::{digits, scan_system};
use types::TestResult;


#[test]
fn the_working_directory_is_system32_on_windows_and_the_root_elsewhere() -> TestResult {
    let expected = if cfg!(windows) { r"C:\Windows\System32" } else { "/" };
    assert_eq!(WORKING_DIRECTORY, expected);
    Ok(())
}


const EVENT: &str =
    "<Event xmlns='x'><System><EventID>4625</EventID><TimeCreated SystemTime='2026-11-03T10:00:00.1Z'/><EventRecordID>7</EventRecordID>\
                     </System><EventData><Data Name='a'>v</Data></EventData></Event>";


const LONG_DIGITS: &str = "123456789012345678901234";


const SMALL_CHUNK: usize = 7;


const ENTITY_PAD: usize = 7_995;


const WIDE: usize = 3_000;


const ID_SEVEN: u64 = 7;


const ID_THREE: u64 = 3;


const ID_FIVE: u64 = 5;


const PAIR: usize = 2;


const EVENT_LOGON_FAILED: u32 = 4625;


const BAD_INPUTS: usize = 10;


const MAX_DIGITS: usize = 5;


const OVERRUN: usize = 5;


const ID_FIFTEEN: u64 = 15;


const HIGH: u16 = 0xD800;


const LOW: u16 = 0xDC00;


const EMOJI_HIGH: u16 = 0xD83D;


const EMOJI_LOW: u16 = 0xDE00;


const BOM: u16 = 0xFEFF;


const SWAPPED_BOM: u16 = 0xFFFE;


const NONCHARACTER: u16 = 0xFFFF;


const REPLACED_SEVEN: u32 = 7;


const LETTER_A: u16 = 0x61;


const CONTROL_ONE: u16 = 0x01;


const CONTROL_ESCAPE: u16 = 0x1B;


fn units_to_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}


fn utf16(text: &str) -> Vec<u8> {
    units_to_bytes(&text.encode_utf16().collect::<Vec<u16>>())
}


fn collect(chunks: &[&[u8]]) -> (Vec<Item>, Stream) {
    let mut stream = Stream::default();
    let mut items = Vec::new();
    chunks
        .iter()
        .for_each(|chunk| feed_bytes(&mut stream, chunk, &mut |item| items.push(item)));
    (items, stream)
}


fn collect_text(text: &str) -> (Vec<Item>, Stream) {
    collect(&[&utf16(text)])
}


#[test]
fn the_split_handles_items_cut_at_every_byte_boundary() -> TestResult {
    let text = format!("{EVENT}\n{EVENT}");
    let bytes = utf16(&text);
    let chunks: Vec<&[u8]> = bytes.chunks(SMALL_CHUNK).collect();
    let (items, stream) = collect(&chunks);
    assert_eq!(items.len(), PAIR);
    assert!(items
        .iter()
        .all(|item| item.kind == ItemKind::Complete && item.text.starts_with("<Event ") && item.text.ends_with("</Event>")));
    assert!(!stream.splitter.inside && !flawed(&stream));
    let single: Vec<&[u8]> = bytes.chunks(1).collect();
    assert_eq!(collect(&single).0.len(), PAIR);
    Ok(())
}


#[test]
fn the_split_ignores_lookalike_tags_and_accepts_a_bare_start_tag() -> TestResult {
    let text = "<EventData><EventID>1</EventID><EventRecordID>2</EventRecordID></Eventx><Event><System/></Event><Event\n a='1'></Event>";
    let (items, _) = collect_text(text);
    assert_eq!(items.len(), PAIR);
    assert!(items.iter().all(|item| item.kind == ItemKind::Complete));
    Ok(())
}


#[test]
fn a_broken_tag_prefix_restarts_the_match() -> TestResult {
    let (items, _) = collect_text("<Eve<Event a='1'></</Event>");
    assert!(matches!(items.as_slice(), [item] if item.kind == ItemKind::Complete));
    Ok(())
}


#[test]
fn a_nested_start_makes_the_item_malformed() -> TestResult {
    let (items, _) = collect_text("<Event a='1'><System/><Event b='2'></Event>");
    assert!(matches!(items.as_slice(), [item] if item.kind == ItemKind::Nested));
    Ok(())
}


#[test]
fn an_item_over_the_item_cap_is_reported_with_its_size_and_a_bounded_head() -> TestResult {
    let body = "x".repeat(MAX_ITEM_BYTES);
    let text = format!("<Event a='1'>{body}</Event>");
    let (items, _) = collect_text(&text);
    assert_eq!(items.len(), 1);
    assert!(items
        .iter()
        .all(|item| item.kind == ItemKind::Oversized && item.size == text.len() && item.text.len() <= MAX_SYSTEM_BYTES));
    Ok(())
}


#[test]
fn the_head_of_an_oversized_item_never_cuts_a_character() -> TestResult {
    let body = "é".repeat(MAX_ITEM_BYTES);
    let text = format!("<Event a='1'>{body}</Event>");
    let (items, _) = collect_text(&text);
    assert!(items
        .iter()
        .all(|item| item.kind == ItemKind::Oversized && item.size == text.len() && item.text.len() <= MAX_SYSTEM_BYTES));
    assert!(items.iter().all(|item| item.text.len() >= MAX_SYSTEM_BYTES - 1));
    Ok(())
}


#[test]
fn an_item_at_the_item_cap_is_complete() -> TestResult {
    let fixed = "<Event a='1'></Event>".len();
    let body = "x".repeat(MAX_ITEM_BYTES - fixed);
    let text = format!("<Event a='1'>{body}</Event>");
    let (items, _) = collect_text(&text);
    assert!(matches!(items.as_slice(), [item] if item.kind == ItemKind::Complete && item.text.len() == MAX_ITEM_BYTES));
    Ok(())
}


#[test]
fn the_caps_count_decoded_text_not_utf16_bytes() -> TestResult {
    let fixed = "<Event a='1'></Event>".len();
    let body = "x".repeat(MAX_ITEM_BYTES - fixed);
    let text = format!("<Event a='1'>{body}</Event>");
    assert_eq!(utf16(&text).len(), MAX_ITEM_BYTES * PAIR);
    let (items, _) = collect_text(&text);
    assert!(items.iter().all(|item| item.kind == ItemKind::Complete));
    Ok(())
}


#[test]
fn a_partial_item_is_taken_once() -> TestResult {
    let (items, mut stream) = collect_text("<Event a='1'><System>");
    assert!(items.is_empty());
    assert!(matches!(partial_item(&mut stream), Some(item) if item.kind == ItemKind::Oversized));
    assert!(partial_item(&mut stream).is_none());
    Ok(())
}


#[test]
fn the_decoder_drops_one_leading_bom_and_keeps_every_other_character() -> TestResult {
    let mut units = vec![BOM];
    units.extend("<Event>é\u{4e2d}\u{ff1c}\u{ff06}\t\r\n</Event>".encode_utf16());
    let (items, stream) = collect(&[&units_to_bytes(&units)]);
    assert!(matches!(items.as_slice(), [item] if item.text == "<Event>é\u{4e2d}\u{ff1c}\u{ff06}\t\r\n</Event>" && item.replaced == 0));
    assert!(!flawed(&stream));
    Ok(())
}


#[test]
fn lone_surrogates_controls_and_noncharacters_are_replaced_and_counted() -> TestResult {
    let mut units: Vec<u16> = "<Event>".encode_utf16().collect();
    units.extend([
        HIGH,
        LETTER_A,
        LOW,
        CONTROL_ONE,
        CONTROL_ESCAPE,
        SWAPPED_BOM,
        NONCHARACTER,
        EMOJI_HIGH,
        EMOJI_LOW,
        HIGH,
        HIGH,
        LOW,
    ]);
    units.extend("</Event>".encode_utf16());
    let (items, stream) = collect(&[&units_to_bytes(&units)]);
    let replaced =
        format!("<Event>{REPLACEMENT}a{REPLACEMENT}{REPLACEMENT}{REPLACEMENT}{REPLACEMENT}{REPLACEMENT}\u{1f600}{REPLACEMENT}\u{10000}</Event>");
    assert!(matches!(items.as_slice(), [item] if item.text == replaced && item.replaced == REPLACED_SEVEN));
    assert!(!flawed(&stream));
    Ok(())
}


#[test]
fn a_surrogate_pair_split_across_chunks_stays_one_character() -> TestResult {
    let mut units: Vec<u16> = "<Event>".encode_utf16().collect();
    units.extend([EMOJI_HIGH, EMOJI_LOW]);
    units.extend("</Event>".encode_utf16());
    let bytes = units_to_bytes(&units);
    let single: Vec<&[u8]> = bytes.chunks(1).collect();
    let (items, _) = collect(&single);
    assert!(matches!(items.as_slice(), [item] if item.text == "<Event>\u{1f600}</Event>" && item.replaced == 0));
    Ok(())
}


#[test]
fn an_odd_trailing_byte_or_a_swapped_bom_flags_the_stream() -> TestResult {
    let mut bytes = utf16(EVENT);
    bytes.push(b'x');
    let (items, stream) = collect(&[&bytes]);
    assert_eq!(items.len(), 1);
    assert!(flawed(&stream));
    let swapped = units_to_bytes(&[SWAPPED_BOM, LETTER_A]);
    let (_, bad) = collect(&[&swapped]);
    assert!(flawed(&bad));
    Ok(())
}


#[test]
fn the_system_scan_reads_both_quote_styles_and_refuses_bad_values() -> TestResult {
    let single = scan_system(EVENT.as_bytes());
    assert_eq!(single.record_id, Some(ID_SEVEN));
    assert_eq!(single.event_id, Some(EVENT_LOGON_FAILED));
    assert_eq!(single.time.as_deref(), Some("2026-11-03T10:00:00.1Z"));
    let double = scan_system(
        b"<System><EventID Qualifiers=\"0\">1</EventID><TimeCreated SystemTime=\"2026-11-03T10:00:00Z\"/><EventRecordID>15</EventRecordID></System>",
    );
    assert_eq!((double.record_id, double.event_id), (Some(ID_FIFTEEN), Some(1)));
    assert_eq!(double.time.as_deref(), Some("2026-11-03T10:00:00Z"));
    let bad_inputs: [&[u8]; BAD_INPUTS] = [
        b"<System><EventRecordID>0</EventRecordID></System>",
        b"<System><EventRecordID>9223372036854775808</EventRecordID></System>",
        b"<System><EventRecordID>99999999999999999999999</EventRecordID></System>",
        b"<System><EventRecordID>1x</EventRecordID></System>",
        b"<System><EventRecordID></EventRecordID></System>",
        b"<System><EventRecordIDx>5</EventRecordIDx></System>",
        b"<System><EventRecordID>5",
        b"<System><TimeCreated SystemTime=2026/></System>",
        b"<System><TimeCreated SystemTime='a b'/></System>",
        b"no system here",
    ];
    bad_inputs.iter().for_each(|input| {
        let info = scan_system(input);
        assert!(info.record_id.is_none(), "{info:?}");
        assert!(info.time.is_none());
    });
    let odd = scan_system(b"<System><EventID>123456</EventID><TimeCreated SystemTime='\xff\xfe'/><EventRecordID Q='1'>5</EventRecordID></System>");
    assert_eq!((odd.record_id, odd.event_id, odd.time), (Some(ID_FIVE), None, None));
    let unclosed = scan_system(b"<System><TimeCreated SystemTime='2026-11-03T10:00:00Z'");
    assert_eq!(unclosed.time, None);
    let after_cap = format!("<System>{}<EventRecordID>5</EventRecordID></System>", " ".repeat(MAX_SYSTEM_BYTES));
    assert_eq!(scan_system(after_cap.as_bytes()), SystemInfo::default());
    assert!(digits(b"", MAX_DIGITS).is_none() && digits(LONG_DIGITS.as_bytes(), LONG_DIGITS.len()).is_none());
    Ok(())
}


#[test]
fn the_cursor_grammar_is_strict() -> TestResult {
    assert!(parse_record_id("1").is_some() && parse_record_id("9223372036854775807").is_some());
    assert!(parse_record_id("").is_none() && parse_record_id("0").is_none() && parse_record_id("01").is_none() && parse_record_id("+1").is_none());
    assert!(parse_record_id("9223372036854775808").is_none() && parse_record_id("99999999999999999999999").is_none());
    assert!(is_time_text("2026-11-03T10:00:00.1234567Z") && !is_time_text("") && !is_time_text("a b") && !is_time_text(&"1".repeat(WIDE)));
    assert_eq!(
        parse_cursor(b"5 2026-11-03T10:00:00Z\n"),
        CursorState::Valid {
            record_id: ID_FIVE,
            time: "2026-11-03T10:00:00Z".to_string(),
            created: None
        }
    );
    assert_eq!(
        parse_cursor(b"5 2026-11-03T10:00:00Z 2026-10-01T08:00:00.000Z\n"),
        CursorState::Valid {
            record_id: ID_FIVE,
            time: "2026-11-03T10:00:00Z".to_string(),
            created: Some("2026-10-01T08:00:00.000Z".to_string())
        }
    );
    assert_eq!(parse_cursor(b"5 2026-11-03T10:00:00Z a b\n"), CursorState::Invalid);
    assert_eq!(parse_cursor(b"5 2026-11-03T10:00:00Z \n"), CursorState::Invalid);
    assert_eq!(parse_cursor(b"5 2026-11-03T10:00:00Z a\xffb\n"), CursorState::Invalid);
    assert_eq!(parse_cursor(b"5 2026-11-03T10:00:00Z\n\n"), CursorState::Invalid);
    assert_eq!(parse_cursor(b"5  x"), CursorState::Invalid);
    let wide = vec![b'1'; usize::try_from(MAX_CURSOR_BYTES).unwrap_or(0) + 1];
    assert_eq!(parse_cursor(&wide), CursorState::Invalid);
    Ok(())
}


#[test]
fn the_cursor_file_round_trips_and_a_missing_one_is_missing() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert_eq!(read_cursor(dir.path(), &SECURITY)?, CursorState::Missing);
    write_cursor(dir.path(), &SECURITY, ID_SEVEN, "2026-11-03T10:00:00Z", None)?;
    assert_eq!(
        read_cursor(dir.path(), &SECURITY)?,
        CursorState::Valid {
            record_id: ID_SEVEN,
            time: "2026-11-03T10:00:00Z".to_string(),
            created: None
        }
    );
    write_cursor(dir.path(), &SECURITY, ID_SEVEN, "2026-11-03T10:00:00Z", Some("2026-10-01T08:00:00Z"))?;
    assert_eq!(
        read_cursor(dir.path(), &SECURITY)?,
        CursorState::Valid {
            record_id: ID_SEVEN,
            time: "2026-11-03T10:00:00Z".to_string(),
            created: Some("2026-10-01T08:00:00Z".to_string())
        }
    );
    assert!(!dir.path().join("security.cursor.tmp").exists());
    Ok(())
}


#[test]
fn a_data_value_over_the_cut_is_marked_with_the_omitted_count() -> TestResult {
    let short = "a".repeat(DATA_CUT_BYTES);
    assert_eq!(cut_value(&short), short);
    let long = "a".repeat(DATA_CUT_BYTES + OVERRUN);
    assert_eq!(cut_value(&long), format!("{}[cut, 5 bytes]", "a".repeat(DATA_CUT_BYTES)));
    let wide = "é".repeat(DATA_CUT_BYTES);
    assert!(cut_value(&wide).ends_with("bytes]") && cut_value(&wide).starts_with('é'));
    let entity = format!("{}&quot;{}", "b".repeat(ENTITY_PAD), "c".repeat(WIDE));
    let cut = cut_value(&entity);
    assert!(cut.starts_with(&"b".repeat(ENTITY_PAD)) && !cut.contains("&quo[") && cut.contains("[cut, "));
    let early = format!("&{}{}", "d".repeat(DATA_CUT_BYTES), "e".repeat(WIDE));
    assert!(cut_value(&early).contains("[cut, "));
    let closed = format!("{}&amp;{}", "f".repeat(DATA_CUT_BYTES - OVERRUN), "g".repeat(WIDE));
    assert!(cut_value(&closed).contains("&amp;"));
    Ok(())
}


#[test]
fn only_data_values_are_cut_and_the_rest_is_kept() -> TestResult {
    let long = "z".repeat(DATA_CUT_BYTES * PAIR);
    let text = format!("<Event><Data Name='a'>{long}</Data><Data Name='b'>ok</Data><Other>{long}</Other></Event>");
    let cut = cut_data_values(&text);
    assert!(cut.contains("[cut, 8000 bytes]</Data><Data Name='b'>ok</Data>"));
    assert!(cut.contains(&format!("<Other>{long}</Other>")));
    let nodata = format!("<A>{long}</Data>");
    assert_eq!(cut_data_values(&nodata), nodata);
    assert_eq!(cut_data_values("plain"), "plain");
    let bare = format!("<Data>{long}</Data>");
    assert!(cut_data_values(&bare).contains("[cut, "));
    Ok(())
}


#[test]
fn the_gap_and_refusal_lines_are_fixed_json() -> TestResult {
    let hole = gap_line(&SECURITY, GapReason::Hole, Some((ID_THREE, ID_FIVE)));
    assert!(hole.contains("\"first_missing\":3") && hole.contains("\"last_missing\":5") && hole.contains("\"count\":3"));
    let invalid = gap_line(&SECURITY, GapReason::CursorInvalid, None);
    assert!(invalid.contains("\"count\":null") && invalid.contains("cursor_invalid"));
    let info = SystemInfo {
        record_id: Some(ID_SEVEN),
        event_id: Some(1),
        time: Some("t".to_string()),
    };
    let malformed = refused_line(&SECURITY, &info, Refusal::Malformed, SMALL_CHUNK);
    assert!(malformed.contains("\"reason\":\"malformed\"") && malformed.contains("\"bytes\":7") && malformed.contains("\"record_id\":7"));
    let ahead = gap_line(&SECURITY, GapReason::CursorAhead, None);
    let stream = gap_line(&SECURITY, GapReason::Utf16, None);
    assert!(ahead.contains("cursor_ahead") && stream.contains("\"reason\":\"utf16\""));
    let forged = forged_line(&SECURITY, Some(ID_THREE), None);
    assert!(forged.contains("\"reason\":\"forged\"") && forged.contains("\"first_id\":3") && forged.contains("\"breaking_id\":null"));
    let stub = refused_line(&SECURITY, &SystemInfo::default(), Refusal::Forged, 0);
    assert!(stub.contains("\"reason\":\"forged\""));
    let oversized = refused_line(&SECURITY, &SystemInfo::default(), Refusal::Oversized, 0);
    assert!(oversized.contains("oversized") && oversized.contains("\"record_id\":null"));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_state_path_through_a_file_is_a_read_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("plain");
    std::fs::write(&file, b"x")?;
    assert!(read_cursor(&file, &SECURITY).is_err());
    Ok(())
}


#[test]
fn the_creation_time_is_read_from_the_gli_text_and_only_when_it_is_time_text() -> TestResult {
    assert_eq!(created_args(&SECURITY), vec!["gli".to_string(), "Security".to_string()]);
    assert_eq!(
        parse_created(b"name: Security\r\ncreationTime: 2026-10-01T08:00:00.000Z\r\nlastAccessTime: x\r\n"),
        Some("2026-10-01T08:00:00.000Z".to_string())
    );
    assert_eq!(
        parse_created(b"  creationTime:2026-10-01T08:00:00Z"),
        Some("2026-10-01T08:00:00Z".to_string())
    );
    assert_eq!(parse_created(b"creationTime: a b\n"), None);
    assert_eq!(parse_created(b"creationTime:\n"), None);
    assert_eq!(parse_created(b"nothing\xff here\n"), None);
    assert_eq!(parse_created(b""), None);
    Ok(())
}
