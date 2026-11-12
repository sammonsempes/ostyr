use siem_schema::traces::{render_traces_ddl, TracesRetention};
use std::io::Write;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ddl = render_traces_ddl(&TracesRetention::default())?;
    write!(std::io::stdout(), "{ddl}")?;
    Ok(())
}
