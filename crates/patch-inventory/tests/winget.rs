mod common;


use base64::Engine;
use common::{device, limits, skipped_count, FailingReader, TestResult};
use patch_inventory::error::WingetError;
use patch_inventory::limits::{MAX_WINGET_ID_BYTES, MAX_WINGET_UPDATES, MAX_WINGET_VERSION_BYTES};
use patch_inventory::model::{Limits, WingetInventory, WingetSkip};
use patch_inventory::winget::parse_winget_updates;
use patch_inventory::winget_script::{WINGET_ENCODED, WINGET_SCRIPT};


const TWO_CAPTURE: &[u8] = include_bytes!("fixtures/winget-lab-two.json");


const ONE_CAPTURE: &[u8] = include_bytes!("fixtures/winget-lab-one.json");


const ZERO_CAPTURE: &[u8] = include_bytes!("fixtures/winget-lab-zero.json");


const UTF16_UNIT_BYTES: usize = 2;


const FOUR: usize = 4;


const MANY_ITEMS: usize = 100_000;


const DEEP: usize = 10_000;


const FOUR_MEBIBYTE_ENTRIES: usize = 2_000_000;


const SMALL_CAP: usize = 16;


const GOOD_ID: &str = "Vendor.Product";


fn good() -> String {
    format!(r#"{{"Id":"{GOOD_ID}","InstalledVersion":"1.0.0","AvailableVersion":"1.1.0","Source":"winget"}}"#)
}


fn with(from: &str, to: &str) -> String {
    good().replace(from, to)
}


fn envelope(elements: &[String]) -> String {
    format!(r#"{{"Updates":[{}]}}"#, elements.join(","))
}


fn parse_text(text: &str) -> Result<WingetInventory, WingetError> {
    parse_winget_updates(&device(), text.as_bytes(), &limits())
}


fn one_element(element: String) -> Result<WingetInventory, WingetError> {
    parse_text(&envelope(&[element]))
}


fn skipped_alone(element: String, reason: WingetSkip) -> TestResult {
    let inventory = parse_text(&envelope(&[element, good().replace(GOOD_ID, "Other.Package")]))?;
    assert_eq!(inventory.updates.len(), 1, "the other element is kept");
    assert_eq!(skipped_count(&inventory.skipped, reason), 1);
    assert_eq!(inventory.skipped.len(), 1);
    Ok(())
}


#[test]
fn encoded_command_is_the_script_in_utf16le_base64() -> TestResult {
    let bytes = base64::engine::general_purpose::STANDARD.decode(WINGET_ENCODED)?;
    let (pairs, remainder) = bytes.as_chunks::<UTF16_UNIT_BYTES>();
    assert!(remainder.is_empty(), "an odd trailing byte");
    let units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    assert_eq!(String::from_utf16(&units)?, WINGET_SCRIPT);
    Ok(())
}


#[test]
fn script_is_ascii_module_qualified_and_filters_on_updates() -> TestResult {
    assert!(WINGET_SCRIPT.is_ascii());
    assert!(WINGET_SCRIPT.contains("Import-Module Microsoft.WinGet.Client"));
    assert!(WINGET_SCRIPT.contains("Microsoft.WinGet.Client\\Get-WinGetPackage"));
    assert!(WINGET_SCRIPT.contains("$_.IsUpdateAvailable"));
    assert!(WINGET_SCRIPT.contains("ConvertTo-Json -InputObject $envelope -Compress"));
    assert!(WINGET_SCRIPT.contains("[\\u007F-\\uFFFF]"));
    Ok(())
}


#[test]
fn lab_capture_is_parsed() -> TestResult {
    let inventory = parse_winget_updates(&device(), TWO_CAPTURE, &limits())?;
    assert_eq!(inventory.updates.len(), FOUR);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::UnknownInstalledVersion), 1);
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::OtherSource), 1);
    let one = parse_winget_updates(&device(), ONE_CAPTURE, &limits())?;
    assert_eq!(one.updates.len(), 1);
    assert!(inventory.updates.iter().all(|update| !update.security && update.architecture == "any"));
    assert!(inventory
        .updates
        .iter()
        .all(|update| update.tenant == "tenant-a" && update.device_id == "device-1"));
    let none = parse_winget_updates(&device(), ZERO_CAPTURE, &limits())?;
    assert!(none.updates.is_empty() && none.skipped.is_empty());
    Ok(())
}


#[test]
fn a_good_element_becomes_an_update() -> TestResult {
    let inventory = one_element(good())?;
    let update = inventory.updates.first().ok_or("no update")?;
    assert_eq!(update.package, GOOD_ID);
    assert_eq!(update.installed_version.as_deref(), Some("1.0.0"));
    assert_eq!(update.candidate_version, "1.1.0");
    assert_eq!(update.origin.as_deref(), Some("winget"));
    assert!(!update.security && update.advisory_id.is_none() && update.severity.is_none());
    assert!(inventory.skipped.is_empty());
    Ok(())
}


#[test]
fn real_winget_version_forms_are_kept_as_text() -> TestResult {
    ["23.01", "8.6", "2.43.0.windows.2", "10.0.19041.1", "20240101", "1.2.3-beta+4"]
        .iter()
        .try_for_each(|version| {
            let inventory = one_element(with(r#""AvailableVersion":"1.1.0""#, &format!(r#""AvailableVersion":"{version}""#)))?;
            assert_eq!(inventory.updates.first().ok_or("no update")?.candidate_version, *version);
            Ok::<(), Box<dyn std::error::Error>>(())
        })
}


#[test]
fn an_unknown_or_empty_installed_version_is_none_and_counted() -> TestResult {
    ["Unknown", ""].iter().try_for_each(|installed| {
        let inventory = one_element(with(r#""InstalledVersion":"1.0.0""#, &format!(r#""InstalledVersion":"{installed}""#)))?;
        assert_eq!(inventory.updates.len(), 1);
        assert!(inventory.updates.first().ok_or("no update")?.installed_version.is_none());
        assert_eq!(skipped_count(&inventory.skipped, WingetSkip::UnknownInstalledVersion), 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn sources_are_a_fixed_list_and_any_other_is_counted() -> TestResult {
    let store = one_element(with(r#""Source":"winget""#, r#""Source":"msstore""#))?;
    assert_eq!(store.updates.first().ok_or("no update")?.origin.as_deref(), Some("msstore"));
    assert!(store.skipped.is_empty());
    ["Evil\\u0027;id", "", "WINGET", "private"].iter().try_for_each(|source| {
        let inventory = one_element(with(r#""Source":"winget""#, &format!(r#""Source":"{source}""#)))?;
        assert_eq!(inventory.updates.len(), 1);
        assert!(inventory.updates.first().ok_or("no update")?.origin.is_none());
        assert_eq!(skipped_count(&inventory.skipped, WingetSkip::OtherSource), 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn ids_outside_the_grammar_are_malformed_alone() -> TestResult {
    let long = "A".repeat(MAX_WINGET_ID_BYTES + 1);
    [
        "-Vendor.Product",
        "Vendor;Product",
        "Vendor Product",
        "Vendor'Product",
        "\\u0022x",
        "",
        ".x",
        &long,
    ]
    .iter()
    .try_for_each(|id| skipped_alone(with(GOOD_ID, id), WingetSkip::Malformed))?;
    let at_limit = "A".repeat(MAX_WINGET_ID_BYTES);
    let ok = one_element(with(GOOD_ID, &at_limit))?;
    assert_eq!(ok.updates.len(), 1);
    ["Microsoft.VCRedist.2015+.x64", "9NBLGGH4NNS1", "a_b-c.d"].iter().try_for_each(|id| {
        let inventory = one_element(with(GOOD_ID, id))?;
        assert_eq!(inventory.updates.len(), 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn versions_outside_the_grammar_are_malformed_alone() -> TestResult {
    let long = "1".repeat(MAX_WINGET_VERSION_BYTES + 1);
    ["-1.0", "< 1.0", "1 0", "1.0\\u0001", &long].iter().try_for_each(|version| {
        skipped_alone(
            with(r#""AvailableVersion":"1.1.0""#, &format!(r#""AvailableVersion":"{version}""#)),
            WingetSkip::Malformed,
        )?;
        skipped_alone(
            with(r#""InstalledVersion":"1.0.0""#, &format!(r#""InstalledVersion":"{version}""#)),
            WingetSkip::Malformed,
        )
    })?;
    skipped_alone(with(r#""AvailableVersion":"1.1.0""#, r#""AvailableVersion":"""#), WingetSkip::Malformed)?;
    let at_limit = "1".repeat(MAX_WINGET_VERSION_BYTES);
    let ok = one_element(with(r#""AvailableVersion":"1.1.0""#, &format!(r#""AvailableVersion":"{at_limit}""#)))?;
    assert_eq!(ok.updates.len(), 1);
    Ok(())
}


#[test]
fn a_missing_or_mistyped_field_is_malformed_alone() -> TestResult {
    [
        r#"{"Id":"Vendor.Product","InstalledVersion":"1.0.0","AvailableVersion":"1.1.0"}"#,
        r#"{"Id":"Vendor.Product","InstalledVersion":"1.0.0","Source":"winget"}"#,
        r#"{"Id":"Vendor.Product","AvailableVersion":"1.1.0","Source":"winget"}"#,
        r#"{"InstalledVersion":"1.0.0","AvailableVersion":"1.1.0","Source":"winget"}"#,
        r#"{"Id":5,"InstalledVersion":"1.0.0","AvailableVersion":"1.1.0","Source":"winget"}"#,
        r#"{"Id":"Vendor.Product","InstalledVersion":null,"AvailableVersion":"1.1.0","Source":"winget"}"#,
        "[]",
        "5",
        "null",
        "{}",
    ]
    .iter()
    .try_for_each(|element| skipped_alone((*element).to_string(), WingetSkip::Malformed))
}


#[test]
fn a_duplicate_id_keeps_the_first_and_counts() -> TestResult {
    let second = with(r#""AvailableVersion":"1.1.0""#, r#""AvailableVersion":"9.9.9""#);
    let inventory = parse_text(&envelope(&[good(), second]))?;
    assert_eq!(inventory.updates.len(), 1);
    assert_eq!(inventory.updates.first().ok_or("no update")?.candidate_version, "1.1.0");
    assert_eq!(skipped_count(&inventory.skipped, WingetSkip::Duplicate), 1);
    Ok(())
}


#[test]
fn output_is_sorted_by_package() -> TestResult {
    let inventory = parse_text(&envelope(&[with(GOOD_ID, "Zed.App"), with(GOOD_ID, "Alpha.App")]))?;
    let names: Vec<&str> = inventory.updates.iter().map(|update| update.package.as_str()).collect();
    assert_eq!(names, ["Alpha.App", "Zed.App"]);
    Ok(())
}


#[test]
fn a_count_bomb_inside_one_element_is_malformed_alone() -> TestResult {
    let many = vec![r#""1""#; MANY_ITEMS].join(",");
    skipped_alone(with(r#""Id":"Vendor.Product""#, &format!(r#""Id":[{many}]"#)), WingetSkip::Malformed)?;
    skipped_alone(with(r#""Source":"winget""#, &format!(r#""Source":[{many}]"#)), WingetSkip::Malformed)?;
    let nested = format!("{}{}", "[".repeat(DEEP), "]".repeat(DEEP));
    skipped_alone(with(r#""Source":"winget""#, &format!(r#""Source":{nested}"#)), WingetSkip::Malformed)
}


#[test]
fn an_extra_field_is_ignored() -> TestResult {
    let inventory = one_element(with(r#""Source":"winget""#, r#""Source":"winget","Name":"Product""#))?;
    assert_eq!(inventory.updates.len(), 1);
    assert!(inventory.skipped.is_empty());
    Ok(())
}


#[test]
fn drop_the_element_count_prescan_mutant_is_caught() -> TestResult {
    let elements: Vec<String> = (0..=MAX_WINGET_UPDATES).map(|_| "{}".to_string()).collect();
    let outcome = parse_text(&envelope(&elements));
    assert!(
        matches!(outcome, Err(WingetError::TooManyUpdates { limit: MAX_WINGET_UPDATES })),
        "{outcome:?}"
    );
    let at_limit: Vec<String> = (0..MAX_WINGET_UPDATES).map(|index| with(GOOD_ID, &format!("Vendor.P{index}"))).collect();
    let accepted = parse_text(&envelope(&at_limit))?;
    assert_eq!(accepted.updates.len(), MAX_WINGET_UPDATES);
    Ok(())
}


#[test]
fn millions_of_elements_in_the_byte_cap_are_refused_by_count() -> TestResult {
    let entries = "{},".repeat(FOUR_MEBIBYTE_ENTRIES / TWO_ELEMENT_DIVISOR);
    let outcome = parse_text(&format!(r#"{{"Updates":[{entries}{{}}]}}"#));
    assert!(matches!(outcome, Err(WingetError::TooManyUpdates { .. })), "{outcome:?}");
    Ok(())
}


const TWO_ELEMENT_DIVISOR: usize = 2;


#[test]
fn an_empty_input_is_no_output_never_an_empty_inventory() -> TestResult {
    [&b""[..], b"\r\n", b"  \t\n"].iter().for_each(|input| {
        let outcome = parse_winget_updates(&device(), *input, &limits());
        assert!(matches!(outcome, Err(WingetError::NoOutput)), "{outcome:?}");
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
        let outcome = parse_winget_updates(&device(), input.as_slice(), &limits());
        assert!(matches!(outcome, Err(WingetError::NotAscii)), "{outcome:?}");
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
        r#"{"Updates":null}"#,
        "{}",
        r#"{"Updates":{}}"#,
        r#"{"Updates":"x"}"#,
    ]
    .iter()
    .for_each(|input| {
        let outcome = parse_text(input);
        assert!(matches!(outcome, Err(WingetError::Malformed { .. })), "{input}: {outcome:?}");
    });
    Ok(())
}


#[test]
fn a_malformed_input_error_carries_a_position_and_no_peer_text() -> TestResult {
    let marker = "SECRET-PEER-MARKER";
    let outcome = parse_text(&format!(r#"{{"Updates":"{marker}"}}"#));
    let error = outcome.err().ok_or("an error was expected")?;
    let shown = format!("{error:?} {error}");
    assert!(matches!(error, WingetError::Malformed { line: 1, .. }), "{shown}");
    assert!(!shown.contains(marker));
    Ok(())
}


#[test]
fn an_oversized_input_is_refused_by_the_byte_cap() -> TestResult {
    let small = Limits {
        max_bytes: SMALL_CAP,
        ..limits()
    };
    let outcome = parse_winget_updates(&device(), TWO_CAPTURE, &small);
    assert!(matches!(outcome, Err(WingetError::Input(_))), "{outcome:?}");
    Ok(())
}


#[test]
fn a_failing_reader_is_an_input_error() -> TestResult {
    let outcome = parse_winget_updates(&device(), FailingReader, &limits());
    assert!(matches!(outcome, Err(WingetError::Input(_))), "{outcome:?}");
    Ok(())
}
