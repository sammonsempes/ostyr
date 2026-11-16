//! Usage: `posture_run <declarations.yaml> <prowler-binary> <workdir> [deadline-seconds]`. Scans every declared cluster, prints the counts and one line per FAIL finding.
#[cfg(unix)]
mod scan {
    use cloud_posture::declarations::load_declarations;
    use cloud_posture::limits::Limits;
    use cloud_posture::model::Status;
    use cloud_posture::report::fail_line;
    use cloud_posture::run::cluster_scan;
    use core_pg::scope::tenant_of;
    use std::error::Error;
    use std::io::{stdout, Write};
    use std::path::Path;
    use std::time::Duration;


    const PROGRAM_ARGUMENT: usize = 1;


    const WORKDIR_ARGUMENT: usize = 2;


    const DEADLINE_ARGUMENT: usize = 3;


    const SCAN_DEADLINE_SECONDS: u64 = 900;


    pub fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
        let arguments = std::env::args().skip(1).collect::<Vec<_>>();
        let declarations = load_declarations(Path::new(arguments.first().ok_or("missing declarations.yaml")?))?;
        let program = arguments.get(PROGRAM_ARGUMENT).ok_or("missing prowler binary")?;
        let workdir = arguments.get(WORKDIR_ARGUMENT).ok_or("missing workdir")?;
        let deadline = arguments
            .get(DEADLINE_ARGUMENT)
            .map_or(Ok(SCAN_DEADLINE_SECONDS), |text| text.parse::<u64>())?;
        let tenant = tenant_of(&declarations.tenant);
        let mut out = stdout();
        declarations
            .refused
            .iter()
            .try_for_each(|index| writeln!(out, "declaration {index} refused"))?;
        declarations.clusters.iter().try_for_each(|cluster| {
            let scan = cluster_scan(
                Path::new(program),
                tenant,
                cluster,
                Path::new(workdir),
                &Limits::default(),
                Duration::from_secs(deadline),
            );
            match scan {
                Ok(findings) => {
                    writeln!(
                        out,
                        "cluster {:?} context {:?} findings={} skipped={:?}",
                        cluster.name,
                        cluster.context,
                        findings.items.len(),
                        findings.skipped
                    )?;
                    findings
                        .items
                        .iter()
                        .filter(|finding| finding.status == Status::Fail)
                        .try_for_each(|finding| writeln!(out, "{}", fail_line(finding)))
                }
                Err(error) => writeln!(out, "cluster {:?} context {:?} error: {error}", cluster.name, cluster.context),
            }
        })?;
        Ok(())
    }
}


#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    scan::run()
}


#[cfg(not(unix))]
fn main() {}
