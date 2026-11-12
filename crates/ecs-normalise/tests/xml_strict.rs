#[path = "common/types.rs"]
mod types;


use ecs_normalise::error::SysmonError;
use ecs_normalise::sysmon_input::parse_event;
use std::error::Error;
use types::TestResult;


const VALID: &str = include_str!("fixtures/winsec_4625.xml");


const EVENT_ID: u32 = 4625;


const MIN_FIXTURES: usize = 20;


fn sysmon_error(text: &str) -> Result<SysmonError, Box<dyn Error>> {
    match parse_event(text) {
        Ok(_) => Err(format!("expected an error for {text}").into()),
        Err(error) => Ok(error),
    }
}


fn outside(text: &str) -> TestResult {
    assert!(matches!(sysmon_error(text)?, SysmonError::OutsideRoot), "{text}");
    Ok(())
}


#[test]
fn an_unnamed_data_is_refused() -> TestResult {
    let text = VALID.replace("</EventData>", "<Data>x</Data></EventData>");
    assert!(matches!(sysmon_error(&text)?, SysmonError::MissingAttribute("Data/Name")));
    let empty = VALID.replace("</EventData>", "<Data/></EventData>");
    assert!(matches!(sysmon_error(&empty)?, SysmonError::MissingAttribute("Data/Name")));
    Ok(())
}


#[test]
fn text_outside_the_root_is_refused() -> TestResult {
    outside(&format!("{VALID}junk"))?;
    outside(&format!("junk{VALID}"))?;
    outside(&format!("{VALID}<![CDATA[x]]>"))?;
    outside(&format!("{VALID}&amp;"))?;
    outside(&format!("{VALID}&#32;"))?;
    Ok(())
}


#[test]
fn whitespace_around_the_root_is_accepted() -> TestResult {
    assert_eq!(parse_event(&format!(" \t\r\n{VALID}\r\n\n"))?.event_id, EVENT_ID);
    assert_eq!(
        parse_event(&format!("<?xml version=\"1.0\"?>\n{VALID}\n<!-- c -->\n"))?.event_id,
        EVENT_ID
    );
    Ok(())
}


#[test]
fn loose_event_ids_are_refused() -> TestResult {
    ["04625", "\u{a0}4625", "4625\u{a0}", "+4625", "004625", "65536", "123456", ""]
        .iter()
        .try_for_each(|id| {
            let text = VALID.replace("<EventID>4625</EventID>", &format!("<EventID>{id}</EventID>"));
            assert!(matches!(sysmon_error(&text)?, SysmonError::BadEventId(_)), "{id}");
            Ok::<(), Box<dyn Error>>(())
        })?;
    let zero = VALID.replace("<EventID>4625</EventID>", "<EventID> 0\n</EventID>");
    assert_eq!(parse_event(&zero)?.event_id, 0);
    let json = r#"{"Event":{"System":{"EventID":"04625"},"EventData":{}}}"#;
    assert!(matches!(sysmon_error(json)?, SysmonError::BadEventId(_)));
    Ok(())
}


fn xml_fixtures() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::read_dir(directory)?
        .map(|entry| entry.map(|found| found.path()))
        .filter(|path| {
            path.as_ref().is_ok_and(|found| {
                let name = found.to_string_lossy();
                name.ends_with(".xml") && (name.contains("/winsec_") || name.contains("/sysmon_"))
            })
        })
        .map(|entry| {
            let file = entry?;
            Ok((file.to_string_lossy().into_owned(), std::fs::read_to_string(&file)?))
        })
        .collect()
}


#[test]
fn every_xml_fixture_refuses_each_tampering() -> TestResult {
    let fixtures = xml_fixtures()?;
    assert!(fixtures.len() > MIN_FIXTURES);
    for (name, text) in &fixtures {
        parse_event(text).map_err(|error| format!("{name} baseline: {error}"))?;
        let unnamed = text.replace("</EventData>", "<Data>x</Data></EventData>");
        assert!(
            matches!(sysmon_error(&unnamed)?, SysmonError::MissingAttribute("Data/Name")),
            "{name} unnamed"
        );
        outside(&format!("{text}junk"))?;
        let start = text.find("<EventID>").map(|at| at + "<EventID>".len()).ok_or("no EventID")?;
        let end = text.find("</EventID>").ok_or("no EventID end")?;
        let id = text.get(start..end).ok_or("slice")?;
        for bad in [format!("0{id}"), format!("\u{a0}{id}"), format!("{id}\u{a0}")] {
            let tampered = text.replace(&format!("<EventID>{id}</EventID>"), &format!("<EventID>{bad}</EventID>"));
            assert!(matches!(sysmon_error(&tampered)?, SysmonError::BadEventId(_)), "{name} {bad:?}");
        }
    }
    Ok(())
}


#[test]
fn any_cdata_outside_the_root_is_refused() -> TestResult {
    outside(&format!("{VALID}<![CDATA[ ]]>"))?;
    outside(&format!("{VALID}<![CDATA[]]>"))?;
    outside(&format!("<![CDATA[]]>{VALID}"))?;
    assert_eq!(parse_event(&format!("{VALID}\n  \r\n"))?.event_id, EVENT_ID);
    Ok(())
}


#[test]
fn form_feed_and_vertical_tab_are_not_id_whitespace() -> TestResult {
    ["\u{c}4625", "4625\u{c}", "\u{b}4625", "4625\u{b}"].iter().try_for_each(|id| {
        let text = VALID.replace("<EventID>4625</EventID>", &format!("<EventID>{id}</EventID>"));
        assert!(matches!(sysmon_error(&text)?, SysmonError::BadEventId(_)), "{id:?}");
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn empty_or_control_data_names_are_refused() -> TestResult {
    ["", "A&#10;B", "A&#9;B", "&#127;"].iter().try_for_each(|name| {
        let text = VALID.replace("</EventData>", &format!("<Data Name=\"{name}\">x</Data></EventData>"));
        assert!(matches!(sysmon_error(&text)?, SysmonError::BadFieldName(_)), "{name:?}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    let json = r#"{"Event":{"System":{"EventID":1},"EventData":{"":"x"}}}"#;
    assert!(matches!(sysmon_error(json)?, SysmonError::BadFieldName(_)));
    Ok(())
}


#[test]
fn smuggled_data_names_keep_their_errors() -> TestResult {
    let twice = VALID.replace(
        "</EventData>",
        "<Data Name=\"TargetUserName\">a</Data><Data Name=\"TargetUserName\">b</Data></EventData>",
    );
    assert!(matches!(sysmon_error(&twice)?, SysmonError::Duplicate(_)));
    let prefixed = VALID.replace("</EventData>", "<Data Name=\"A\" x:Name=\"B\">a</Data></EventData>");
    assert!(matches!(sysmon_error(&prefixed)?, SysmonError::PrefixedAttribute(_)));
    Ok(())
}
