mod common;


use base64::Engine;
use common::{device, limits, skipped_count, FailingReader, TestResult};
use patch_inventory::error::WindowsError;
use patch_inventory::limits::MAX_WINDOWS_UPDATES;
use patch_inventory::model::{Limits, WindowsInventory, WindowsSeverity, WindowsSkip};
use patch_inventory::windows::parse_windows_updates;
use patch_inventory::wua_script::{WUA_SEARCH_ENCODED, WUA_SEARCH_SCRIPT};


const THREE: &[u8] = include_bytes!("fixtures/wua-lab-three.json");


const ONE: &[u8] = include_bytes!("fixtures/wua-lab-one.json");


const ZERO: &[u8] = include_bytes!("fixtures/wua-lab-zero.json");


const CACHE: &[u8] = include_bytes!("fixtures/wua-lab-cache.json");


const HIDDEN: &[u8] = include_bytes!("fixtures/wua-lab-hidden.json");


const GOOD_ID: &str = "11111111-2222-3333-4444-555555555555";


const SECURITY_CATEGORY: &str = "0fa1201d-4330-4fa8-8ae9-b877473b6441";


const OTHER_CATEGORY: &str = "e6cf1350-c01b-414d-a61f-263d14d133b4";


const TWO: usize = 2;


const FOUR: usize = 4;


const CODE_OK: i64 = 2;


const CODE_PARTIAL: i64 = 3;


const CAPTURED_REVISION: u32 = 200;


const HIGH_REVISION: u32 = 9;


const THREE_COUNT: usize = 3;


const NINE: usize = 9;


const TOO_MANY_UPDATES: usize = 1001;


const MANY_ITEMS: usize = 100_000;


const DEEP: usize = 10_000;


const TITLE_BYTES: usize = 10_240;


const TITLE_CAP: usize = 512;


const SMALL_CAP: usize = 16;


const UTF16_UNIT_BYTES: usize = 2;


const REVISION_TOO_BIG: u64 = 4_294_967_296;


const REVISION_MAX: u64 = 4_294_967_295;


const CODE_FOUR: i64 = 4;


const CODE_FIVE: i64 = 5;


fn good() -> String {
    format!(
        r#"{{"UpdateID":"{GOOD_ID}","RevisionNumber":7,"KBArticleIDs":["5031234"],"Title":"Update","MsrcSeverity":"","CategoryIDs":[],"IsHidden":false,"IsMandatory":false,"RebootBehavior":0}}"#
    )
}


fn with(from: &str, to: &str) -> String {
    good().replace(from, to)
}


fn with_title(title: &str) -> String {
    with(r#""Title":"Update""#, &format!(r#""Title":"{title}""#))
}


fn envelope(code: i64, elements: &[String]) -> String {
    format!(r#"{{"ResultCode":{code},"Updates":[{}]}}"#, elements.join(","))
}


fn parse_text(text: &str) -> Result<WindowsInventory, WindowsError> {
    parse_windows_updates(&device(), text.as_bytes(), &limits())
}


fn one_element(element: String) -> Result<WindowsInventory, WindowsError> {
    parse_text(&envelope(CODE_OK, &[element]))
}


fn json_escape(hex: &str) -> String {
    format!("{}u{hex}", '\\')
}


fn skipped_alone(element: String, reason: WindowsSkip) -> TestResult {
    let inventory = parse_text(&envelope(
        CODE_OK,
        &[element, good().replace(GOOD_ID, "99999999-2222-3333-4444-555555555555")],
    ))?;
    assert_eq!(inventory.updates.len(), 1, "the other element is kept");
    assert_eq!(skipped_count(&inventory.skipped, reason), 1);
    assert_eq!(inventory.skipped.len(), 1);
    Ok(())
}


#[test]
fn encoded_command_is_the_script_in_utf16le_base64() -> TestResult {
    let bytes = base64::engine::general_purpose::STANDARD.decode(WUA_SEARCH_ENCODED)?;
    let units: Vec<u16> = bytes
        .as_chunks::<UTF16_UNIT_BYTES>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    assert_eq!(String::from_utf16(&units)?, WUA_SEARCH_SCRIPT);
    Ok(())
}


#[test]
fn script_is_ascii_searches_missing_software_and_keeps_hidden_updates() -> TestResult {
    assert!(WUA_SEARCH_SCRIPT.is_ascii());
    assert!(WUA_SEARCH_SCRIPT.contains(r#"Search("IsInstalled=0 and Type='Software'")"#));
    assert!(!WUA_SEARCH_SCRIPT.contains("IsHidden=0"));
    assert!(WUA_SEARCH_SCRIPT.contains("ConvertTo-Json -InputObject $envelope -Compress -Depth 4"));
    assert!(WUA_SEARCH_SCRIPT.contains("[\\u007F-\\uFFFF]"));
    Ok(())
}


#[test]
fn lab_capture_of_three_updates_is_parsed() -> TestResult {
    let inventory = parse_windows_updates(&device(), THREE, &limits())?;
    assert!(!inventory.partial);
    assert!(inventory.skipped.is_empty());
    assert_eq!(inventory.updates.len(), THREE_COUNT);
    let first = inventory.updates.first().ok_or("no first update")?;
    assert_eq!(first.update_id, SECURITY_CATEGORY);
    assert_eq!(first.revision, CAPTURED_REVISION);
    assert_eq!(first.title, "Cumulative \u{ff02}quoted\u{ff02} \\ \u{ff3c} caf\u{e9} \u{1f600} <b>&");
    assert_eq!(first.severity, Some(WindowsSeverity::Critical));
    assert!(first.security && first.hidden && !first.mandatory);
    assert_eq!(first.kb_ids, ["5031234"]);
    assert_eq!(first.reboot_behavior, 1);
    assert_eq!(first.tenant, "tenant-a");
    assert_eq!(first.device_id, "device-1");
    let no_kb = inventory.updates.get(1).ok_or("no second update")?;
    assert!(no_kb.kb_ids.is_empty() && no_kb.mandatory && !no_kb.security && no_kb.severity.is_none());
    let two_kb = inventory.updates.get(TWO).ok_or("no third update")?;
    assert_eq!(two_kb.kb_ids, ["5031234", "5039999"]);
    assert_eq!(two_kb.severity, Some(WindowsSeverity::Low));
    assert!(two_kb.security);
    Ok(())
}


#[test]
fn lab_capture_of_one_update_and_of_none_are_parsed() -> TestResult {
    let single = parse_windows_updates(&device(), ONE, &limits())?;
    assert_eq!(single.updates.len(), 1);
    let none = parse_windows_updates(&device(), ZERO, &limits())?;
    assert!(none.updates.is_empty() && none.skipped.is_empty() && !none.partial);
    Ok(())
}


#[test]
fn lab_capture_of_the_local_update_cache_marks_security_by_category_only() -> TestResult {
    let inventory = parse_windows_updates(&device(), CACHE, &limits())?;
    assert_eq!(inventory.updates.len(), FOUR);
    assert!(inventory.skipped.is_empty() && !inventory.partial);
    assert!(inventory.updates.iter().all(|update| update.severity.is_none()));
    assert_eq!(inventory.updates.iter().filter(|update| update.security).count(), TWO);
    Ok(())
}


#[test]
fn a_search_that_did_not_run_is_a_named_failure() -> TestResult {
    let outcome = parse_text(&envelope(0, &[]));
    assert!(matches!(outcome, Err(WindowsError::SearchFailed { code: 0 })), "{outcome:?}");
    Ok(())
}


#[test]
fn result_code_three_is_kept_and_flagged_partial() -> TestResult {
    let inventory = parse_text(&envelope(CODE_PARTIAL, &[good()]))?;
    assert!(inventory.partial);
    assert_eq!(inventory.updates.len(), 1);
    Ok(())
}


#[test]
fn accept_result_code_four_mutant_is_caught() -> TestResult {
    [CODE_FOUR, CODE_FIVE, 1, -1].iter().for_each(|code| {
        let outcome = parse_text(&envelope(*code, &[good()]));
        assert!(
            matches!(outcome, Err(WindowsError::SearchFailed { code: seen }) if seen == *code),
            "{outcome:?}"
        );
    });
    Ok(())
}


#[test]
fn an_empty_input_is_no_output_never_an_empty_inventory() -> TestResult {
    [&b""[..], b"\r\n", b"  \t\n"].iter().for_each(|input| {
        let outcome = parse_windows_updates(&device(), *input, &limits());
        assert!(matches!(outcome, Err(WindowsError::NoOutput)), "{outcome:?}");
    });
    Ok(())
}


#[test]
fn non_ascii_input_is_refused_by_name() -> TestResult {
    let utf16: Vec<u8> = "{}".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let inputs: Vec<Vec<u8>> = vec![
        b"\xef\xbb\xbf{}".to_vec(),
        utf16,
        b"{\0}".to_vec(),
        "{\"a\":\"caf\u{e9}\"}".as_bytes().to_vec(),
        b"{\"a\":\"\xff\"}".to_vec(),
    ];
    inputs.iter().for_each(|input| {
        let outcome = parse_windows_updates(&device(), input.as_slice(), &limits());
        assert!(matches!(outcome, Err(WindowsError::NotAscii)), "{outcome:?}");
    });
    Ok(())
}


#[test]
fn a_bare_array_a_scalar_and_a_missing_updates_list_are_malformed() -> TestResult {
    [
        "[]",
        "2",
        "null",
        "{",
        r#"{"ResultCode":"2","Updates":[]}"#,
        r#"{"ResultCode":2}"#,
        r#"{"ResultCode":2,"Updates":{}}"#,
    ]
    .iter()
    .for_each(|input| {
        let outcome = parse_text(input);
        assert!(matches!(outcome, Err(WindowsError::Malformed { .. })), "{input}: {outcome:?}");
    });
    Ok(())
}


#[test]
fn a_malformed_input_error_carries_a_position_and_no_peer_text() -> TestResult {
    let marker = "SECRET-PEER-MARKER";
    let outcome = parse_text(&format!(r#"{{"ResultCode":"{marker}"}}"#));
    let error = outcome.err().ok_or("an error was expected")?;
    let shown = format!("{error:?} {error}");
    assert!(matches!(error, WindowsError::Malformed { line: 1, .. }), "{shown}");
    assert!(!shown.contains(marker));
    Ok(())
}


#[test]
fn an_oversized_input_is_refused_by_the_byte_cap() -> TestResult {
    let small = Limits {
        max_bytes: SMALL_CAP,
        ..limits()
    };
    let outcome = parse_windows_updates(&device(), THREE, &small);
    assert!(matches!(outcome, Err(WindowsError::Input(_))), "{outcome:?}");
    Ok(())
}


#[test]
fn a_failing_reader_is_an_input_error() -> TestResult {
    let outcome = parse_windows_updates(&device(), FailingReader, &limits());
    assert!(matches!(outcome, Err(WindowsError::Input(_))), "{outcome:?}");
    Ok(())
}


#[test]
fn drop_the_element_count_prescan_mutant_is_caught() -> TestResult {
    let elements: Vec<String> = (0..TOO_MANY_UPDATES).map(|_| "{}".to_string()).collect();
    let outcome = parse_text(&envelope(CODE_OK, &elements));
    assert!(
        matches!(outcome, Err(WindowsError::TooManyUpdates { limit: MAX_WINDOWS_UPDATES })),
        "{outcome:?}"
    );
    let at_limit: Vec<String> = (0..MAX_WINDOWS_UPDATES)
        .map(|index| good().replace(GOOD_ID, &format!("11111111-2222-3333-4444-{index:012}")))
        .collect();
    let accepted = parse_text(&envelope(CODE_OK, &at_limit))?;
    assert_eq!(accepted.updates.len(), MAX_WINDOWS_UPDATES);
    Ok(())
}


#[test]
fn a_hundred_thousand_kb_entries_are_refused_by_count_and_the_rest_is_kept() -> TestResult {
    let kbs = vec![r#""5031234""#; MANY_ITEMS].join(",");
    skipped_alone(with(r#"["5031234"]"#, &format!("[{kbs}]")), WindowsSkip::TooManyItems)
}


#[test]
fn nine_kbs_or_nine_categories_are_too_many_items() -> TestResult {
    let nine_kbs = format!("[{}]", [r#""5031234""#; NINE].join(","));
    skipped_alone(with(r#"["5031234"]"#, &nine_kbs), WindowsSkip::TooManyItems)?;
    let nine_categories = format!(r#"["{SECURITY_CATEGORY}"{}]"#, format!(r#","{OTHER_CATEGORY}""#).repeat(NINE - 1));
    skipped_alone(
        with(r#""CategoryIDs":[]"#, &format!(r#""CategoryIDs":{nine_categories}"#)),
        WindowsSkip::TooManyItems,
    )
}


#[test]
fn eight_items_are_accepted() -> TestResult {
    let eight = format!("[{}]", [r#""5031234""#; NINE - 1].join(","));
    let inventory = one_element(with(r#"["5031234"]"#, &eight))?;
    assert_eq!(inventory.updates.first().ok_or("no update")?.kb_ids.len(), NINE - 1);
    Ok(())
}


#[test]
fn nesting_ten_thousand_levels_deep_is_refused_without_overflow() -> TestResult {
    let nested = format!("{}{}", "[".repeat(DEEP), "]".repeat(DEEP));
    skipped_alone(with(r#""CategoryIDs":[]"#, &format!(r#""CategoryIDs":{nested}"#)), WindowsSkip::Malformed)
}


#[test]
fn accept_a_kb_with_a_leading_dash_mutant_is_caught() -> TestResult {
    [
        "-5031234",
        "5031234; rm",
        "50312",
        "123456789",
        "",
        " 5031234",
        "5031234 ",
        "50312x4",
        &"1".repeat(TITLE_CAP / TWO),
    ]
    .iter()
    .try_for_each(|kb| skipped_alone(with(r#"["5031234"]"#, &format!(r#"["{kb}"]"#)), WindowsSkip::Malformed))?;
    ["123456", "12345678"].iter().try_for_each(|kb| {
        let inventory = one_element(with(r#"["5031234"]"#, &format!(r#"["{kb}"]"#)))?;
        assert_eq!(inventory.updates.len(), 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn guids_are_checked_and_stored_lowercase() -> TestResult {
    [
        "11111111-2222-3333-4444-55555555555",
        " 11111111-2222-3333-4444-555555555555",
        "11111111-2222-3333-4444-555555555555 ",
        "{11111111-2222-3333-4444-555555555555}",
        "11111111-2222-3333-4444-55555555555g",
        "11111111222233334444555555555555",
        "11111111-2222-3333-4444-555555555555-1",
        "",
    ]
    .iter()
    .try_for_each(|id| skipped_alone(with(GOOD_ID, id), WindowsSkip::Malformed))?;
    let inventory = one_element(with(GOOD_ID, "ABCDEF12-2222-3333-4444-55555555555A"))?;
    assert_eq!(
        inventory.updates.first().ok_or("no update")?.update_id,
        "abcdef12-2222-3333-4444-55555555555a"
    );
    skipped_alone(with(r#""CategoryIDs":[]"#, r#""CategoryIDs":["not-a-guid"]"#), WindowsSkip::Malformed)?;
    skipped_alone(with(r#""CategoryIDs":[]"#, r#""CategoryIDs":[5]"#), WindowsSkip::Malformed)
}


#[test]
fn revisions_and_reboot_behaviours_are_range_checked() -> TestResult {
    ["0", "-1", "1.5", "\"7\"", &REVISION_TOO_BIG.to_string(), "null"]
        .iter()
        .try_for_each(|revision| {
            skipped_alone(
                with(r#""RevisionNumber":7"#, &format!(r#""RevisionNumber":{revision}"#)),
                WindowsSkip::Malformed,
            )
        })?;
    let top = one_element(with(r#""RevisionNumber":7"#, &format!(r#""RevisionNumber":{REVISION_MAX}"#)))?;
    assert_eq!(top.updates.first().ok_or("no update")?.revision, u32::MAX);
    ["3", "-1", "256", "1.0", "true"].iter().try_for_each(|reboot| {
        skipped_alone(
            with(r#""RebootBehavior":0"#, &format!(r#""RebootBehavior":{reboot}"#)),
            WindowsSkip::Malformed,
        )
    })?;
    ["0", "1", "2"].iter().try_for_each(|reboot| {
        let inventory = one_element(with(r#""RebootBehavior":0"#, &format!(r#""RebootBehavior":{reboot}"#)))?;
        assert_eq!(inventory.updates.len(), 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn missing_and_mistyped_fields_are_malformed_alone() -> TestResult {
    [
        r#""IsHidden":false"#,
        r#""IsMandatory":false"#,
        r#""Title":"Update""#,
        r#""RevisionNumber":7"#,
        r#""KBArticleIDs":["5031234"]"#,
    ]
    .iter()
    .try_for_each(|field| {
        skipped_alone(
            good().replace(&format!("{field},"), "").replace(&format!(",{field}"), ""),
            WindowsSkip::Malformed,
        )
    })?;
    skipped_alone(with(r#""IsHidden":false"#, r#""IsHidden":"false""#), WindowsSkip::Malformed)?;
    skipped_alone(with(r#""IsMandatory":false"#, r#""IsMandatory":0"#), WindowsSkip::Malformed)?;
    skipped_alone(with(r#""Title":"Update""#, r#""Title":null"#), WindowsSkip::Malformed)?;
    skipped_alone(with(r#""MsrcSeverity":"""#, r#""MsrcSeverity":5"#), WindowsSkip::Malformed)?;
    skipped_alone(with(r#"["5031234"]"#, "[5031234]"), WindowsSkip::Malformed)?;
    skipped_alone(with(r#"["5031234"]"#, r#""5031234""#), WindowsSkip::Malformed)?;
    skipped_alone("[]".to_string(), WindowsSkip::Malformed)?;
    skipped_alone(with_title(&format!("{}d800", json_escape(""))), WindowsSkip::Malformed)
}


#[test]
fn titles_with_control_or_invisible_characters_are_skipped_alone() -> TestResult {
    ["001b", "0000", "202e", "200b", "feff", "2028", "0085", "007f"]
        .iter()
        .try_for_each(|hex| skipped_alone(with_title(&format!("Up{}date", json_escape(hex))), WindowsSkip::ControlCharacters))
}


#[test]
fn a_long_title_is_cut_with_a_visible_marker_and_the_record_is_kept() -> TestResult {
    let long = "a".repeat(TITLE_BYTES);
    let cut = one_element(with_title(&long))?;
    let title = &cut.updates.first().ok_or("no update")?.title;
    assert_eq!(title, &format!("{}[cut, {} bytes]", "a".repeat(TITLE_CAP), TITLE_BYTES - TITLE_CAP));
    let exact = one_element(with_title(&"a".repeat(TITLE_CAP)))?;
    assert_eq!(exact.updates.first().ok_or("no update")?.title.len(), TITLE_CAP);
    let wide = "\u{20ac}".repeat(TITLE_CAP);
    let wide_cut = one_element(with_title(&json_escape("20ac").repeat(TITLE_CAP)))?;
    let wide_title = &wide_cut.updates.first().ok_or("no update")?.title;
    let kept = TITLE_CAP / THREE_COUNT * THREE_COUNT;
    assert_eq!(
        wide_title,
        &format!("{}[cut, {} bytes]", "\u{20ac}".repeat(kept / THREE_COUNT), wide.len() - kept)
    );
    Ok(())
}


#[test]
fn severities_map_to_the_four_learn_words() -> TestResult {
    [
        ("Critical", WindowsSeverity::Critical),
        ("Important", WindowsSeverity::Important),
        ("Moderate", WindowsSeverity::Moderate),
        ("Low", WindowsSeverity::Low),
    ]
    .iter()
    .try_for_each(|(word, severity)| {
        let inventory = one_element(with(r#""MsrcSeverity":"""#, &format!(r#""MsrcSeverity":"{word}""#)))?;
        let update = inventory.updates.first().ok_or("no update")?;
        assert_eq!(update.severity, Some(*severity));
        assert!(update.security);
        assert!(inventory.skipped.is_empty());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn empty_null_and_absent_severities_are_none_without_a_security_flag() -> TestResult {
    [r#""MsrcSeverity":null"#, r#""MsrcSeverity":"""#, ""].iter().try_for_each(|replacement| {
        let element = if replacement.is_empty() {
            good().replace(r#""MsrcSeverity":"","#, "")
        } else {
            with(r#""MsrcSeverity":"""#, replacement)
        };
        let inventory = one_element(element)?;
        let update = inventory.updates.first().ok_or("no update")?;
        assert!(update.severity.is_none() && !update.security);
        assert!(inventory.skipped.is_empty());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn an_unknown_severity_word_keeps_the_record_as_security_and_is_counted() -> TestResult {
    let inventory = one_element(with(r#""MsrcSeverity":"""#, r#""MsrcSeverity":"Sehr wichtig""#))?;
    let update = inventory.updates.first().ok_or("no update")?;
    assert!(update.security && update.severity.is_none());
    assert_eq!(skipped_count(&inventory.skipped, WindowsSkip::UnknownSeverity), 1);
    let lowercase = one_element(with(r#""MsrcSeverity":"""#, r#""MsrcSeverity":"critical""#))?;
    assert_eq!(skipped_count(&lowercase.skipped, WindowsSkip::UnknownSeverity), 1);
    Ok(())
}


#[test]
fn drop_the_category_id_security_rule_mutant_is_caught() -> TestResult {
    let by_category = one_element(with(
        r#""CategoryIDs":[]"#,
        &format!(r#""CategoryIDs":["{OTHER_CATEGORY}","{}"]"#, SECURITY_CATEGORY.to_uppercase()),
    ))?;
    let update = by_category.updates.first().ok_or("no update")?;
    assert!(update.security && update.severity.is_none());
    assert_eq!(update.category_ids, [OTHER_CATEGORY, SECURITY_CATEGORY]);
    let other = one_element(with(r#""CategoryIDs":[]"#, &format!(r#""CategoryIDs":["{OTHER_CATEGORY}"]"#)))?;
    assert!(!other.updates.first().ok_or("no update")?.security);
    Ok(())
}


#[test]
fn hidden_and_mandatory_flags_are_kept() -> TestResult {
    let inventory = one_element(with(r#""IsHidden":false,"IsMandatory":false"#, r#""IsHidden":true,"IsMandatory":true"#))?;
    let update = inventory.updates.first().ok_or("no update")?;
    assert!(update.hidden && update.mandatory);
    Ok(())
}


#[test]
fn duplicates_keep_the_highest_revision_then_the_first_and_are_counted() -> TestResult {
    let element = |revision: &str, title: &str| {
        with(r#""RevisionNumber":7"#, &format!(r#""RevisionNumber":{revision}"#)).replace(r#""Title":"Update""#, &format!(r#""Title":"{title}""#))
    };
    let inventory = parse_text(&envelope(
        CODE_OK,
        &[
            element("5", "low-first"),
            element("9", "high-middle"),
            element("8", "lower-last"),
            element("9", "equal-last"),
        ],
    ))?;
    assert_eq!(inventory.updates.len(), 1);
    let kept = inventory.updates.first().ok_or("no update")?;
    assert_eq!((kept.revision, kept.title.as_str()), (HIGH_REVISION, "high-middle"));
    assert_eq!(skipped_count(&inventory.skipped, WindowsSkip::Duplicate), THREE_COUNT);
    Ok(())
}


#[test]
fn output_is_sorted_by_update_id_and_stamped_with_the_device() -> TestResult {
    let ids = [
        "cccccccc-2222-3333-4444-555555555555",
        "aaaaaaaa-2222-3333-4444-555555555555",
        "BBBBBBBB-2222-3333-4444-555555555555",
    ];
    let elements: Vec<String> = ids.iter().map(|id| with(GOOD_ID, id)).collect();
    let inventory = parse_text(&envelope(CODE_OK, &elements))?;
    let seen: Vec<&str> = inventory.updates.iter().map(|update| update.update_id.as_str()).collect();
    assert_eq!(
        seen,
        [
            "aaaaaaaa-2222-3333-4444-555555555555",
            "bbbbbbbb-2222-3333-4444-555555555555",
            "cccccccc-2222-3333-4444-555555555555"
        ]
    );
    assert!(inventory
        .updates
        .iter()
        .all(|update| update.tenant == "tenant-a" && update.device_id == "device-1"));
    Ok(())
}


#[test]
fn lab_capture_with_a_hidden_missing_security_update_lists_it_as_hidden() -> TestResult {
    let inventory = parse_windows_updates(&device(), HIDDEN, &limits())?;
    let hidden: Vec<_> = inventory.updates.iter().filter(|update| update.hidden).collect();
    assert_eq!(hidden.len(), 1);
    assert!(hidden
        .iter()
        .all(|update| update.security && update.update_id == "6a98e36f-eea1-47cc-b2b3-b662124a1b32"));
    Ok(())
}
