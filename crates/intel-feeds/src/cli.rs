use crate::config::FeedsFile;
use crate::load::summarise;
use crate::model::FeedSummary;
use crate::run::{collect_feeds, export_feeds, write_iocs};
use crate::types::{ClockFn, LoadFn, OpenFn};
use core_config::reload::{current_config, reload, ReloadEngine};
use core_config::reload_cli::{write_outcome, QUIT_COMMAND};
use std::io::{self, BufRead, Write};


/// IOCs go to `out`, summaries and command results to `report`.
pub struct Session<'a> {
    pub engine: &'a ReloadEngine<FeedsFile>,
    pub clock: &'a ClockFn<'a>,
    pub open: &'a OpenFn<'a>,
    pub load: &'a LoadFn<'a>,
    pub out: &'a mut dyn Write,
    pub report: &'a mut dyn Write,
}


pub fn write_summaries(summaries: &[FeedSummary], report: &mut dyn Write) -> io::Result<()> {
    summaries.iter().try_for_each(|summary| {
        serde_json::to_writer(&mut *report, summary)?;
        writeln!(report)
    })
}


/// `run` parses every feed of the current configuration, loads the IOCs into ClickHouse when `clickhouse` is set, `export` writes a STIX bundle under the export policy, `reload` reloads the file, `feeds` lists the feed names.
pub fn run_command(session: &mut Session, command: &str) -> io::Result<()> {
    match command.trim() {
        "run" => {
            let config = current_config(session.engine);
            let now = (session.clock)();
            let (index, summaries) = collect_feeds(&config, now, session.open);
            write_iocs(&index, &mut *session.out)?;
            write_summaries(&summaries, &mut *session.report)?;
            config.clickhouse.as_ref().map_or(Ok(()), |clickhouse| {
                let iocs: Vec<_> = index.into_values().collect();
                let loaded = (session.load)(clickhouse, &iocs, &config.feeds, now);
                serde_json::to_writer(&mut *session.report, &summarise(&loaded))?;
                writeln!(session.report)
            })
        }
        "export" => {
            let config = current_config(session.engine);
            let (summaries, exported) = export_feeds(&config, (session.clock)(), session.open, &mut *session.out)?;
            write_summaries(&summaries, &mut *session.report)?;
            serde_json::to_writer(&mut *session.report, &exported)?;
            writeln!(session.report)
        }
        "reload" => write_outcome(&reload(session.engine), &mut session.report),
        "feeds" => current_config(session.engine)
            .feeds
            .iter()
            .try_for_each(|feed| writeln!(session.report, "{}", feed.name)),
        other => writeln!(session.report, "unknown command `{other}`"),
    }
}


/// Reads commands until `quit` or end of input.
pub fn run_session(session: &mut Session, input: &mut dyn BufRead) -> io::Result<()> {
    input
        .lines()
        .take_while(|line| line.as_ref().map_or(true, |text| text.trim() != QUIT_COMMAND))
        .try_for_each(|line| line.and_then(|command| run_command(session, &command)))
}
