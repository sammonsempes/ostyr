use crate::error::PollError;
use crate::model::{Channel, Newest, PollEnv, PollTotals, RunEnd, RunRequest, Stream, SystemInfo, CHANNEL_NOT_FOUND_EXIT, NEWEST_COUNT};
use crate::stream::{feed_bytes, partial_item};
use crate::system::scan_system;


pub fn newest_args(channel: &Channel) -> Vec<String> {
    vec![
        "qe".to_string(),
        channel.name.to_string(),
        format!("/c:{NEWEST_COUNT}"),
        "/rd:true".to_string(),
        "/f:xml".to_string(),
        "/uni:true".to_string(),
    ]
}


pub fn classify(end: RunEnd, first: Option<SystemInfo>, torn: bool) -> Newest {
    match (end, first) {
        (RunEnd::Done, None) if !torn => Newest::Empty,
        (RunEnd::Done, Some(info)) => info.record_id.map_or(Newest::Failed, Newest::Id),
        (RunEnd::Failed(Some(CHANNEL_NOT_FOUND_EXIT)), _) => Newest::Absent,
        _ => Newest::Failed,
    }
}


pub fn query_newest(env: &mut PollEnv<'_>, channel: &Channel, totals: &mut PollTotals) -> Result<Newest, PollError> {
    let args = newest_args(channel);
    let request = RunRequest {
        program: env.program,
        args: &args,
        max_bytes: env.max_output_bytes,
        deadline_seconds: env.deadline_seconds,
    };
    let mut stream = Stream::default();
    let mut first: Option<SystemInfo> = None;
    let mut count = 0u64;
    let end = (env.run)(&request, &mut |chunk| {
        feed_bytes(&mut stream, chunk, &mut |item| {
            count += 1;
            if first.is_none() {
                first = Some(scan_system(item.text.as_bytes()));
            }
        });
    })?;
    totals.forged += count.saturating_sub(1);
    let torn = partial_item(&mut stream).is_some();
    Ok(classify(end, first, torn))
}
