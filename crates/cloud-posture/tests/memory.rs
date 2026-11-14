#[path = "common/types.rs"]
mod types;


use cloud_posture::error::ParseError;
use cloud_posture::limits::{Limits, DEFAULT_MAX_BYTES, DEFAULT_MAX_FINDINGS};
use cloud_posture::model::{Skipped, Status};
use cloud_posture::prowler::parse_prowler_ocsf;
use std::collections::BTreeMap;
use std::error::Error;
use types::TestResult;


const MAX_UID_UNITS: usize = 2_000;


const DISPLAY_FLOOD_CHARACTERS: [usize; 3] = [147, 146, 73];


const INDEX_DIGITS: usize = 6;


const MEMORY_CHILD_ENV: &str = "CLOUD_POSTURE_MEMORY_CHILD";


const ADDRESS_SPACE_LIMIT: &str = "--as=450000000";


const HEAD: &str =
    r#"[{"finding_info":{"uid":"u","title":"t"},"metadata":{"event_code":"c"},"status_code":"FAIL","severity":"High","time":1794646103,"#;


const RESOURCE: &str = r#""resources":[{"uid":"r","type":"T","namespace":"n"}],"#;


const UNMAPPED_HEAD: &str = r#""unmapped":{"provider":"kubernetes","provider_uid":"a""#;


fn repeated(head: &str, unit: &str, tail: &str) -> Result<String, Box<dyn Error>> {
    let count = (usize::try_from(DEFAULT_MAX_BYTES)? - head.len() - tail.len()) / unit.len();
    Ok(format!("{head}{}{tail}", unit.repeat(count)))
}


fn root_flood() -> Result<String, Box<dyn Error>> {
    repeated("[", "{},", "{}]")
}


fn unmapped_keys() -> Result<String, Box<dyn Error>> {
    repeated(&format!("{HEAD}{RESOURCE}{UNMAPPED_HEAD},"), r#""k":1,"#, r#""z":1}}]"#)
}


fn compliance_keys() -> Result<String, Box<dyn Error>> {
    repeated(
        &format!("{HEAD}{RESOURCE}{UNMAPPED_HEAD},\"compliance\":{{"),
        r#""k":[],"#,
        r#""z":[]}}}]"#,
    )
}


fn resources_flood() -> Result<String, Box<dyn Error>> {
    repeated(
        &format!(r#"{HEAD}"unmapped":{{"provider":"kubernetes","provider_uid":"a"}},"resources":["#),
        "{},",
        "{}]}]",
    )
}


fn labels_flood() -> Result<String, Box<dyn Error>> {
    repeated(
        &format!(r#"{HEAD}"unmapped":{{"provider":"kubernetes","provider_uid":"a"}},"resources":[{{"uid":"r","type":"T","labels":["#),
        "1,",
        "1]}]}]",
    )
}


fn uid_flood() -> String {
    let findings = (0..DEFAULT_MAX_FINDINGS)
        .map(|index| {
            format!(
                r#"{{"finding_info":{{"uid":"u{index}","title":"t"}},"metadata":{{"event_code":"c"}},"status_code":"FAIL","severity":"High","time":1794646103,{RESOURCE}"unmapped":{{"provider":"kubernetes","provider_uid":"a"}},"cloud":null}}"#
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", findings.join(","))
}


fn long_uid_flood(unit: &str) -> Result<String, Box<dyn Error>> {
    let uid_units = MAX_UID_UNITS;
    let head = r#"{"finding_info":{"uid":""#;
    let tail = format!(
        r#"","title":"t"}},"metadata":{{"event_code":"c"}},"status_code":"FAIL","severity":"High","time":1794646103,{RESOURCE}"unmapped":{{"provider":"kubernetes","provider_uid":"a"}},"cloud":null}}"#
    );
    let one = head.len() + uid_units * unit.len() + tail.len() + INDEX_DIGITS + 1;
    let count = usize::try_from(DEFAULT_MAX_BYTES)? / one;
    let findings = (0..count)
        .map(|index| format!("{head}{}{index:0width$}{tail}", unit.repeat(uid_units - 1), width = INDEX_DIGITS))
        .collect::<Vec<_>>();
    Ok(format!("[{}]", findings.join(",")))
}


fn display_flood(characters: usize) -> Result<String, Box<dyn Error>> {
    let text = "\u{700}".repeat(characters);
    let head = r#"{"finding_info":{"uid":""#;
    let tail = format!(
        r#"","title":"{text}"}},"metadata":{{"event_code":"c"}},"status_code":"FAIL","severity":"High","status_detail":"{text}","time":1794646103,{RESOURCE}"unmapped":{{"provider":"kubernetes","provider_uid":"a"}},"cloud":null}}"#
    );
    let one = head.len() + tail.len() + INDEX_DIGITS + 1;
    let count = (usize::try_from(DEFAULT_MAX_BYTES)? / one).min(DEFAULT_MAX_FINDINGS);
    let findings = (0..count)
        .map(|index| format!("{head}{index:0width$}{tail}", width = INDEX_DIGITS))
        .collect::<Vec<_>>();
    Ok(format!("[{}]", findings.join(",")))
}


fn parse(input: &str) -> Result<Result<usize, Skipped>, ParseError> {
    let parsed = parse_prowler_ocsf(input.as_bytes(), "lab", "a", &Limits::default())?;
    Ok(if parsed.items.is_empty() {
        Err(parsed.skipped)
    } else {
        Ok(parsed.items.len())
    })
}


fn every_flood_is_refused() -> TestResult {
    let kept = parse(&uid_flood());
    assert!(
        matches!(kept, Ok(Ok(DEFAULT_MAX_FINDINGS))),
        "every finding uid is its own identity: {kept:?}"
    );
    [r"\\", "a"].iter().try_for_each(|unit| {
        let flood = long_uid_flood(unit)?;
        let outcome = parse(&flood)?;
        assert!(matches!(outcome, Ok(count) if count > 0), "{outcome:?}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    DISPLAY_FLOOD_CHARACTERS.iter().try_for_each(|characters| {
        let flood = display_flood(*characters)?;
        let outcome = parse(&flood)?;
        assert!(matches!(outcome, Ok(count) if count > 0), "{outcome:?}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    let root = parse(&root_flood()?);
    assert!(matches!(root, Err(ParseError::TooManyFindings { .. })), "{root:?}");
    let refused_alone = Skipped {
        bad_field: 1,
        refused_by_status: BTreeMap::from([(Status::Fail, 1)]),
        ..Skipped::default()
    };
    [unmapped_keys, compliance_keys, resources_flood, labels_flood]
        .iter()
        .try_for_each(|build| {
            let outcome = parse(&build()?)?;
            assert_eq!(outcome, Err(refused_alone.clone()));
            Ok::<(), Box<dyn Error>>(())
        })
}


#[test]
fn memory_limited_child_refuses_every_flood() -> TestResult {
    std::env::var(MEMORY_CHILD_ENV).map_or(Ok(()), |_marker| every_flood_is_refused())
}


#[test]
fn floods_at_the_byte_cap_are_refused_under_an_address_space_limit() -> TestResult {
    let output = std::process::Command::new("prlimit")
        .arg(ADDRESS_SPACE_LIMIT)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--exact", "memory_limited_child_refuses_every_flood", "--test-threads=1"])
        .env(MEMORY_CHILD_ENV, "1")
        .output()?;
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "the child test did not run");
    Ok(())
}
