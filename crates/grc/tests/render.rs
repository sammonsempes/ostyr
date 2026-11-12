#[path = "common/types.rs"]
mod types;


use grc::evidence::make_evidence;
use grc::model::{ControlResult, ControlStatus, Report};
use grc::render::{status_name, write_report};
use std::io::Write;
use types::TestResult;


const OBSERVED: i64 = 1_800_000_000;


const VALUE: f64 = 5.0;


const LAST_LINE: usize = 2;


const VERSION: u32 = 1;


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("disk full"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn report() -> Report {
    let evidence = make_evidence("edr.share", VALUE, OBSERVED, "edr");
    Report {
        tenant: "acme".to_owned(),
        framework: "demo".to_owned(),
        version: VERSION,
        results: vec![
            ControlResult {
                control: "C1".to_owned(),
                status: ControlStatus::Compliant,
                evidence: Some(evidence),
            },
            ControlResult {
                control: "C2".to_owned(),
                status: ControlStatus::NotAssessable,
                evidence: None,
            },
        ],
    }
}


#[test]
fn every_status_has_a_name() -> TestResult {
    assert_eq!(status_name(ControlStatus::Compliant), "compliant");
    assert_eq!(status_name(ControlStatus::PartiallyCompliant), "partially compliant");
    assert_eq!(status_name(ControlStatus::NonCompliant), "non compliant");
    assert_eq!(status_name(ControlStatus::NotAssessable), "not assessable");
    Ok(())
}


#[test]
fn a_report_prints_one_line_per_control() -> TestResult {
    let mut out = Vec::new();
    write_report(&mut out, &report())?;
    let text = String::from_utf8(out)?;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.first(), Some(&"acme\tdemo\t1"));
    assert!(lines
        .get(1)
        .is_some_and(|line| line.starts_with("C1\tcompliant\t") && !line.ends_with('-')));
    assert_eq!(lines.get(LAST_LINE), Some(&"C2\tnot assessable\t-"));
    Ok(())
}


#[test]
fn a_write_failure_is_reported() -> TestResult {
    assert!(write_report(&mut FailingWriter, &report()).is_err());
    Ok(())
}
