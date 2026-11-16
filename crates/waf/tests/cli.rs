use serde_json::json;
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use waf::cli::{render_to, render_to_capped};
use waf::error::WafError;


const GOLDEN_JSON: &str = "tests/fixtures/two_routes.json";


const GOLDEN_YAML: &str = "tests/fixtures/two_routes.yaml";


struct Budget {
    remaining: usize,
}


impl Write for Budget {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.remaining {
            Err(io::Error::other("budget exhausted"))
        } else {
            self.remaining -= buffer.len();
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }
}


#[test]
fn the_golden_file_is_written_and_nothing_is_reported() -> Result<(), Box<dyn Error>> {
    let mut json_out = Vec::new();
    let mut report = Vec::new();
    let refused = render_to(&mut fs::read(GOLDEN_YAML)?.as_slice(), &mut json_out, &mut report)?;
    assert_eq!(refused, 0);
    assert_eq!(String::from_utf8(json_out)?, fs::read_to_string(GOLDEN_JSON)?);
    assert!(report.is_empty());
    Ok(())
}


#[test]
fn a_refused_route_is_reported() -> Result<(), Box<dyn Error>> {
    let text = json!({"routes": [{"hosts": ["a b"], "backends": ["a:1"]}]}).to_string();
    let mut report = Vec::new();
    let refused = render_to(&mut text.as_bytes(), &mut Vec::new(), &mut report)?;
    assert_eq!(refused, 1);
    assert_eq!(String::from_utf8(report)?, "route 0 refused: invalid host\n");
    Ok(())
}


#[test]
fn failing_dependencies_are_errors() -> Result<(), Box<dyn Error>> {
    let source = fs::read(GOLDEN_YAML)?;
    let text = json!({"routes": [{"hosts": ["a b"], "backends": ["a:1"]}]}).to_string();
    let expected = fs::read_to_string(GOLDEN_JSON)?.len();
    let unread = render_to(&mut Broken, &mut Vec::new(), &mut Vec::new());
    assert!(matches!(unread, Err(WafError::Config(_))));
    let no_json = render_to(&mut source.as_slice(), &mut Budget { remaining: 0 }, &mut Vec::new());
    assert!(matches!(no_json, Err(WafError::Output(_))));
    let no_newline = render_to(&mut source.as_slice(), &mut Budget { remaining: expected - 1 }, &mut Vec::new());
    assert!(matches!(no_newline, Err(WafError::Output(_))));
    let no_report = render_to(&mut text.as_bytes(), &mut Vec::new(), &mut Budget { remaining: 0 });
    assert!(matches!(no_report, Err(WafError::Output(_))));
    Ok(())
}


#[test]
fn a_json_over_the_cap_is_refused_before_anything_is_written() -> Result<(), Box<dyn Error>> {
    let mut json_out = Vec::new();
    let mut report = Vec::new();
    let yaml = fs::read(GOLDEN_YAML)?;
    let golden_len = fs::read_to_string(GOLDEN_JSON)?.trim_end().len();
    let refused = render_to_capped(&mut yaml.as_slice(), &mut json_out, &mut report, golden_len - 1);
    assert!(matches!(refused, Err(WafError::OutputTooLarge { max, .. }) if max == golden_len - 1));
    assert!(json_out.is_empty());
    let accepted = render_to_capped(&mut yaml.as_slice(), &mut json_out, &mut report, golden_len)?;
    assert_eq!(accepted, 0);
    Ok(())
}
