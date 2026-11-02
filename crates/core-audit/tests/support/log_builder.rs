use crate::sample::entry;
use core_audit::log::{append, genesis_log};
use std::error::Error;


pub fn build_log(count: usize) -> Result<(Vec<String>, String), Box<dyn Error>> {
    let log = genesis_log(Vec::new());
    (0..count).try_for_each(|index| {
        entry(index)
            .map_err(|error| error.to_string())
            .and_then(|new| append(&log, new).map(|_| ()).map_err(|error| error.to_string()))
    })?;
    let state = log.state.into_inner()?;
    let text = String::from_utf8(state.writer)?;
    Ok((text.split_inclusive('\n').map(str::to_owned).collect(), state.head))
}
