#[path = "common/types.rs"]
mod types;


use ecs_normalise::error::{SysmonError, WinSecError};
use ecs_normalise::sysmon_input::{parse_event, RawEvent};
use ecs_normalise::winsec::normalise_security;
use std::error::Error;
use types::TestResult;


const SECURITY: &str = "Microsoft-Windows-Security-Auditing";


const JOINED_ID: u32 = 462;


fn system(inner: &str) -> String {
    format!("<Event><System><Provider Name=\"{SECURITY}\"/>{inner}</System><EventData><Data Name=\"a\">1</Data></EventData></Event>")
}


fn refused(text: &str) -> Result<SysmonError, Box<dyn Error>> {
    match parse_event(text) {
        Ok(_) => Err(format!("expected an error for {text}").into()),
        Err(error) => Ok(error),
    }
}


fn accepted(text: &str) -> Result<RawEvent, Box<dyn Error>> {
    Ok(parse_event(text)?)
}


#[test]
fn x17_child_in_channel() -> TestResult {
    let text = system("<EventID>4624</EventID><Channel>Sysmon<x/></Channel><Channel>Security</Channel>");
    assert!(matches!(refused(&text)?, SysmonError::UnexpectedChild));
    assert!(matches!(normalise_security(&text), Err(WinSecError::Event(SysmonError::UnexpectedChild))));
    Ok(())
}


#[test]
fn x20_eventid_override() -> TestResult {
    let text = system("<EventID>1<x/></EventID><EventID>4625</EventID>");
    assert!(matches!(refused(&text)?, SysmonError::UnexpectedChild));
    Ok(())
}


#[test]
fn children_inside_computer_and_data_are_refused() -> TestResult {
    let computer = system("<EventID>1</EventID><Computer>A<x/></Computer><Computer>B</Computer>");
    assert!(matches!(refused(&computer)?, SysmonError::UnexpectedChild));
    let data = "<Event><System><EventID>1</EventID></System><EventData><Data Name=\"a\">1<x/></Data><Data Name=\"a\">2</Data></EventData></Event>";
    assert!(matches!(refused(data)?, SysmonError::UnexpectedChild));
    Ok(())
}


#[test]
fn x19_data_with_child() -> TestResult {
    let named = "<Event><System><EventID>1</EventID></System><EventData><Data Name=\"a\"><x>1</x></Data></EventData></Event>";
    assert!(matches!(refused(named)?, SysmonError::UnexpectedChild));
    let unnamed = "<Event><System><EventID>1</EventID></System><EventData><Data><x/></Data></EventData></Event>";
    assert!(matches!(refused(unnamed)?, SysmonError::UnexpectedChild));
    Ok(())
}


#[test]
fn nested_children_at_depth_two_and_three_are_refused() -> TestResult {
    let deep = system("<EventID>1<a><b><c/></b></a></EventID>");
    assert!(matches!(refused(&deep)?, SysmonError::UnexpectedChild));
    let channel = system("<EventID>1</EventID><Channel><a><b/></a></Channel>");
    assert!(matches!(refused(&channel)?, SysmonError::UnexpectedChild));
    Ok(())
}


#[test]
fn a_comment_or_instruction_inside_a_leaf_joins_the_text() -> TestResult {
    let text = system("<EventID>4<!-- c -->6<?pi x?>2</EventID><Channel>Sec<!-- c -->urity</Channel>");
    let event = accepted(&text)?;
    assert_eq!(event.event_id, JOINED_ID);
    assert_eq!(event.channel.as_deref(), Some("Security"));
    Ok(())
}


#[test]
fn x10_provider_noname_then_name() -> TestResult {
    let text = format!("<Event><System><Provider/><Provider Name=\"{SECURITY}\"/><EventID>1</EventID></System><EventData/></Event>");
    assert!(matches!(refused(&text)?, SysmonError::MissingAttribute("Provider/Name")));
    Ok(())
}


#[test]
fn x18_timecreated_noattr_then() -> TestResult {
    let text = "<Event><System><TimeCreated/><TimeCreated SystemTime=\"2026-11-03T10:00:00Z\"/><EventID>1</EventID></System></Event>";
    assert!(matches!(refused(text)?, SysmonError::MissingAttribute("TimeCreated/SystemTime")));
    Ok(())
}


#[test]
fn x13_two_system() -> TestResult {
    let text = "<Event><System><EventID>1</EventID></System><System><EventID>2</EventID></System></Event>";
    assert!(matches!(refused(text)?, SysmonError::Duplicate("System")));
    Ok(())
}


#[test]
fn x11_two_eventdata() -> TestResult {
    let text = "<Event><System><EventID>1</EventID></System><EventData/><EventData><Data Name=\"a\">1</Data></EventData></Event>";
    assert!(matches!(refused(text)?, SysmonError::Duplicate("EventData")));
    Ok(())
}


#[test]
fn the_new_errors_display() -> TestResult {
    assert!(SysmonError::UnexpectedChild.to_string().contains("inside"));
    assert!(SysmonError::MissingAttribute("x").to_string().contains("`x`"));
    Ok(())
}
