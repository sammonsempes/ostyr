use ebpf_probes::drain::MAX_DRAIN_PER_POLL;
use ebpf_probes::loader::{load_exec_probe, poll_exec};
use ebpf_probes::object::EXEC_OBJECT_PATH;
use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::AtomicBool;


const DEFAULT_POLLS: u32 = 20;


const SHOWN_RECORDS: usize = 4;


fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let mut arguments = std::env::args().skip(1);
    let path = arguments.next().unwrap_or_else(|| EXEC_OBJECT_PATH.to_string());
    let polls = arguments.next().map_or(Ok(DEFAULT_POLLS), |text| text.parse())?;
    let mut probe = load_exec_probe(Path::new(&path))?;
    let stop = AtomicBool::new(false);
    let mut stdout = std::io::stdout();
    writeln!(stdout, "loaded {path}, {polls} polls")?;
    let done = poll_exec(&mut probe, &stop, polls, MAX_DRAIN_PER_POLL, &mut |drained| {
        let shown: Vec<String> = drained
            .records
            .iter()
            .take(SHOWN_RECORDS)
            .map(|record| format!(" [pid={} ppid={} uid={} comm={}]", record.pid, record.ppid, record.uid, record.comm))
            .collect();
        if let Err(error) = writeln!(std::io::stdout(), "report {:?}{}", drained.report, shown.concat()) {
            tracing::warn!("stdout closed: {error}");
        }
    });
    writeln!(stdout, "polled {done} times")?;
    Ok(())
}
