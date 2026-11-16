use grc::error::GrcError;
use grc::evaluate::evaluate_framework;
use grc::evidence::verify_evidence;
use grc::export::{to_csv, to_json, to_markdown};
use grc::inputs::{load_indicators, load_manual};
use grc::load::load_framework;
use grc::render::{write_report, write_risks};
use grc::report::{build_report, ComplianceReport};
use grc::risk::{load_risks, Register};
use grc::risk_eval::evaluate_risks;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const USAGE: &str = "usage: grc_evaluate <framework.yaml> <indicators.json> <manual.yaml> <tenant> <now RFC 3339> [<control>=<old digest>] [--risks <risks.yaml>] [--format markdown|csv|json] [--out <path>]";


const RISKS_FLAG: &str = "--risks";


const FORMAT_FLAG: &str = "--format";


const OUT_FLAG: &str = "--out";


const FRAMEWORK_ARGUMENT: usize = 1;


const INDICATORS_ARGUMENT: usize = 2;


const MANUAL_ARGUMENT: usize = 3;


const TENANT_ARGUMENT: usize = 4;


const REQUIRED_ARGUMENTS: usize = 5;


const CHECK_ARGUMENT: usize = 6;


fn flag_value<'a>(arguments: &'a [String], flag: &str) -> Option<&'a str> {
    arguments
        .iter()
        .position(|text| text == flag)
        .and_then(|position| arguments.get(position + 1))
        .map(String::as_str)
}


fn render(format: &str, compliance: &ComplianceReport) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut rendered = Vec::new();
    match format {
        "markdown" => rendered.extend_from_slice(to_markdown(compliance).as_bytes()),
        "csv" => to_csv(compliance, &mut rendered)?,
        "json" => to_json(compliance, &mut rendered)?,
        _ => Err(USAGE)?,
    }
    Ok(rendered)
}


fn write_output(out: Option<&str>, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    match out {
        Some(path) => {
            let target = Path::new(path);
            let directory = target.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
            temporary.write_all(bytes)?;
            temporary.persist(target)?;
        }
        None => stdout().write_all(bytes)?,
    }
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() <= REQUIRED_ARGUMENTS {
        Err(USAGE.into())
    } else {
        let argument = |index: usize| arguments.get(index).map_or("", String::as_str);
        let framework = load_framework(Path::new(argument(FRAMEWORK_ARGUMENT)))?;
        let indicators = load_indicators(Path::new(argument(INDICATORS_ARGUMENT)))?;
        let manual = load_manual(Path::new(argument(MANUAL_ARGUMENT)))?;
        let now = OffsetDateTime::parse(argument(REQUIRED_ARGUMENTS), &Rfc3339)?;
        let report = evaluate_framework(argument(TENANT_ARGUMENT), &framework, &indicators, &manual, now)?;
        let risks_path = flag_value(&arguments, RISKS_FLAG);
        let register = match risks_path {
            Some(path) => load_risks(Path::new(path), &framework)?,
            None => Register {
                tenant: argument(TENANT_ARGUMENT).to_owned(),
                risks: Vec::new(),
                actions: Vec::new(),
            },
        };
        if let Some(format) = flag_value(&arguments, FORMAT_FLAG) {
            let compliance = build_report(&framework, &report, &register, now.date())?;
            write_output(flag_value(&arguments, OUT_FLAG), &render(format, &compliance)?)?;
        } else {
            write_report(&mut stdout(), &report)?;
            if risks_path.is_some() {
                write_risks(&mut stdout(), &evaluate_risks(&register, &report, now.date())?)?;
            }
        }
        if let Some((control, old_digest)) = argument(CHECK_ARGUMENT).split_once('=') {
            let mut evidence = report
                .results
                .iter()
                .find(|result| result.control == control)
                .and_then(|result| result.evidence.clone())
                .ok_or("no evidence for that control")?;
            evidence.sha256 = old_digest.to_owned();
            let verdict = match verify_evidence(&evidence) {
                Ok(()) => "old digest accepted".to_owned(),
                Err(GrcError::EvidenceMismatch) => "old digest refused: the evidence changed".to_owned(),
                Err(other) => other.to_string(),
            };
            writeln!(stdout(), "{verdict}")?;
        }
        Ok(())
    }
}
