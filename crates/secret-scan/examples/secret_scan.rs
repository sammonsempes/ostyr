//! Usage: `secret_scan <gitleaks> <rules> <dir> <tenant> <scope-id> <timeout-seconds>`, with `TMPDIR` a root-only directory (`/tmp` 1777 is refused).

#[cfg(unix)]
mod unix_run {
    use core_pg::scope::tenant_scope;
    use secret_scan::alerting::secret_alerts;
    use secret_scan::allow::check_normalised;
    use secret_scan::copy::sweep_stale;
    use secret_scan::model::{Limits, ScanScope};
    use secret_scan::scan::{run_settings, scan_directory, ScanTarget};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::Duration;


    const ARGUMENTS: usize = 6;


    const PRLIMIT: &str = "/usr/bin/prlimit";


    const MEMORY_BYTES: u64 = 16 << 30;


    const FILE_BYTES: u64 = 1 << 30;


    const POLL_MILLIS: u64 = 100;


    const STALE_SECONDS: u64 = 7200;


    const MICROS_PER_SECOND: u64 = 1_000_000;


    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let mut out = std::io::stdout();
        let arguments: Vec<String> = std::env::args().skip(1).collect();
        let [program, rules, directory, tenant, scope_id, timeout] = <&[String; ARGUMENTS]>::try_from(arguments.as_slice())
            .map_err(|_| "usage: secret_scan <gitleaks> <rules> <dir> <tenant> <scope-id> <timeout-seconds>")?;
        let work_dir = std::env::temp_dir();
        check_normalised(&work_dir)?;
        let swept = sweep_stale(&work_dir, rustix::process::geteuid().as_raw(), Duration::from_secs(STALE_SECONDS))?;
        writeln!(out, "swept={swept}")?;
        let run = run_settings(
            PathBuf::from(PRLIMIT),
            PathBuf::from(rules),
            work_dir,
            MEMORY_BYTES,
            FILE_BYTES,
            POLL_MILLIS,
        );
        let scope = ScanScope::default();
        let target = ScanTarget {
            tenant,
            scope_id,
            scope: &scope,
        };
        let report = scan_directory(
            &PathBuf::from(program),
            &PathBuf::from(directory),
            &target,
            &Limits::default(),
            timeout.parse()?,
            &run,
        )?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let alerts = secret_alerts(&tenant_scope(tenant)?, &report, now.saturating_mul(MICROS_PER_SECOND));
        writeln!(
            out,
            "findings={} malformed={} skipped={} alerts={}",
            report.findings.len(),
            report.malformed,
            report.skipped,
            alerts.len()
        )?;
        writeln!(out, "copy={:?}", report.copy)?;
        report.findings.iter().try_for_each(|finding| {
            writeln!(
                out,
                "{} {}:{}-{} {}",
                finding.rule_id, finding.file, finding.start_line, finding.end_line, finding.excerpt
            )
        })?;
        Ok(())
    }
}


#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix_run::run()
}


#[cfg(not(unix))]
fn main() {}
