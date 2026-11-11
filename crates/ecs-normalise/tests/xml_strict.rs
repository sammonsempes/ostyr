#[path = "common/types.rs"]
mod types;


use ecs_normalise::error::SysmonError;
use ecs_normalise::sysmon_input::parse_event;
use std::error::Error;
use types::TestResult;


const VALID: &str = include_str!("fixtures/winsec_4625.xml");


const EVENT_ID: u32 = 4625;


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
