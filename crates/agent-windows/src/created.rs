use crate::cursor::is_time_text;
use crate::error::PollError;
use crate::model::{Channel, PollEnv, PollTotals, RunEnd, RunRequest};


const CREATION_KEY: &str = "creationTime:";


pub fn created_args(channel: &Channel) -> Vec<String> {
    vec!["gli".to_string(), channel.name.to_string()]
}


pub fn parse_created(output: &[u8]) -> Option<String> {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| line.trim().strip_prefix(CREATION_KEY).map(|rest| rest.trim().to_string()))
        .filter(|text| is_time_text(text))
}


pub fn query_created(env: &mut PollEnv<'_>, channel: &Channel, totals: &mut PollTotals) -> Result<Option<String>, PollError> {
    let args = created_args(channel);
    let request = RunRequest {
        program: env.program,
        args: &args,
        max_bytes: env.max_output_bytes,
        deadline_seconds: env.deadline_seconds,
        environment: None,
    };
    let mut output: Vec<u8> = Vec::new();
    let end = (env.run)(&request, &mut |chunk| output.extend_from_slice(chunk))?;
    let created = (end == RunEnd::Done).then(|| parse_created(&output)).flatten();
    totals.creation_unknown += u64::from(created.is_none());
    Ok(created)
}
