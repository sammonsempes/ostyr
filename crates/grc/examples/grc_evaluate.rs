use grc::error::GrcError;
use grc::evaluate::evaluate_framework;
use grc::evidence::verify_evidence;
use grc::inputs::{load_indicators, load_manual};
use grc::load::load_framework;
use grc::render::{write_report, write_risks};
use grc::risk::load_risks;
use grc::risk_eval::evaluate_risks;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const USAGE: &str =
    "usage: grc_evaluate <framework.yaml> <indicators.json> <manual.yaml> <tenant> <now RFC 3339> [<control>=<old digest>] [--risks <risks.yaml>]";


const RISKS_FLAG: &str = "--risks";


const FRAMEWORK_ARGUMENT: usize = 1;


const INDICATORS_ARGUMENT: usize = 2;


const MANUAL_ARGUMENT: usize = 3;


const TENANT_ARGUMENT: usize = 4;


const REQUIRED_ARGUMENTS: usize = 5;


const CHECK_ARGUMENT: usize = 6;


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
        write_report(&mut stdout(), &report)?;
        if let Some(risks_path) = arguments
            .iter()
            .position(|text| text == RISKS_FLAG)
            .and_then(|flag| arguments.get(flag + 1))
        {
            let register = load_risks(Path::new(risks_path), &framework)?;
            write_risks(&mut stdout(), &evaluate_risks(&register, &report, now.date())?)?;
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
