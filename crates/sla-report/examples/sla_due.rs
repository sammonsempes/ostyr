use sla_report::schedule::{due_periods, format_rfc3339, load_report_file, MAX_DUE_PERIODS};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;


const USAGE: &str = "usage: sla_due <file> <now-seconds> [<last-done-end>]";


fn scenario(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let (file, now, last_done) = match arguments {
        [file, now] => Ok((file, now, None)),
        [file, now, last_done] => Ok((file, now, Some(last_done.parse::<i64>()?))),
        _ => Err(USAGE),
    }?;
    let report_file = load_report_file(Path::new(file))?;
    let now_seconds = now.parse::<i64>()?;
    let mut out = stdout();
    for definition in &report_file.reports {
        for period in due_periods(definition, last_done, now_seconds, MAX_DUE_PERIODS)? {
            writeln!(
                out,
                "{} {} {} {} {}",
                definition.id,
                definition.tenant,
                format_rfc3339(period.start)?,
                format_rfc3339(period.end)?,
                period.end
            )?;
        }
    }
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    scenario(&arguments)
}
