//! Live proof: `posture_store <pg.yaml> migrate | store | bulk | twin | read | page-sql`, see `USAGE`.

use alerts::pg::pg_executor;
use cloud_posture::error::StoreError;
use cloud_posture::limits::Limits;
use cloud_posture::model::{Finding, Findings, FindingsPage, Severity, Skipped, Status};
use cloud_posture::page::{read_findings, refusal_pending, PAGE_SQL};
use cloud_posture::prowler::parse_prowler_ocsf;
use cloud_posture::store::{replace_run, MIGRATIONS, MIGRATION_NAMESPACE, STORE_DEADLINE};
use cloud_posture::text::{escaped_whole, shown};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use core_pg::settings::parse_settings;
use std::error::Error;
use std::fs::File;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;


const USAGE: &str = "usage: posture_store <pg.yaml> migrate | store <tenant> <account> <run> <now_micros> <ocsf.json> \
                     | read <tenant> <account> <limit> [cursor] | page-sql \
                     | bulk <tenant> <account> <run> <now_micros> <count> <prefix> [nul] | twin <tenant> <account> <run> <now_micros>";


const BULK_TIME: i64 = 1_700_000_000;


const SEVERITIES: [Severity; 3] = [Severity::High, Severity::Medium, Severity::Critical];


fn finding_of(account: &str, uid: String, resource_uid: String, status: Status, severity: Severity) -> Finding {
    Finding {
        uid,
        check_id: "check_one".to_owned(),
        status,
        severity,
        provider: "aws".to_owned(),
        account: account.to_owned(),
        region: "eu-west-1".to_owned(),
        resource_uid,
        resource_type: "AwsResource".to_owned(),
        time_unix: BULK_TIME,
        title: "title".to_owned(),
        title_cut: 0,
        detail: "detail".to_owned(),
        detail_cut: 0,
    }
}


fn bulk_findings(account: &str, count: usize, prefix: &str, nul: bool) -> Vec<Finding> {
    let mut items: Vec<Finding> = (0..count)
        .map(|index| {
            let severity = SEVERITIES.get(index % SEVERITIES.len()).copied().unwrap_or(Severity::Low);
            finding_of(
                account,
                format!("{prefix}-{index}"),
                format!("res-{prefix}-{index}"),
                Status::Pass,
                severity,
            )
        })
        .collect();
    if nul {
        items.push(Finding {
            detail: "bad\0detail".to_owned(),
            ..finding_of(
                account,
                format!("{prefix}-nul"),
                format!("res-{prefix}-nul"),
                Status::Fail,
                Severity::High,
            )
        });
    }
    items
}


fn findings_of(tenant: &str, account: &str, items: Vec<Finding>) -> Result<Findings, Box<dyn Error>> {
    Ok(Findings {
        tenant: tenant_scope(tenant)?,
        account: account.to_owned(),
        items,
        skipped: Skipped::default(),
    })
}


fn print_page(page: &Result<FindingsPage, StoreError>) -> Result<(), Box<dyn Error>> {
    let mut out = stdout();
    match page {
        Ok(found) => {
            writeln!(
                out,
                "run {:?} refusal_pending={}",
                found.run,
                found.run.as_ref().is_some_and(refusal_pending)
            )?;
            writeln!(out, "unservable={} next={:?} rows={}", found.unservable, found.next, found.items.len())?;
            found.items.iter().try_for_each(|finding| {
                writeln!(
                    out,
                    "row {:?} {:?} {:?} {:?}",
                    escaped_whole(&finding.uid),
                    finding.severity,
                    finding.status,
                    shown(&finding.title, finding.title_cut)
                )
            })?;
        }
        Err(error) => writeln!(out, "error {error:?}")?,
    }
    Ok(())
}


async fn scenario(settings_file: &Path, words: &[String]) -> Result<(), Box<dyn Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    let exec = pg_executor(&client, STORE_DEADLINE);
    let prepared = match words {
        [word] if word == "migrate" => {
            migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, STORE_DEADLINE).await?;
            None
        }
        [word] if word == "page-sql" => {
            writeln!(stdout(), "{PAGE_SQL}")?;
            None
        }
        [word, tenant, account, limit, flags @ ..] if word == "read" => {
            let scope = tenant_scope(tenant)?;
            let page = read_findings(&exec, &scope, account, flags.first().map(String::as_str), limit.parse()?).await;
            print_page(&page)?;
            None
        }
        [word, tenant, account, run, now, file] if word == "store" => {
            let parsed = parse_prowler_ocsf(File::open(file)?, tenant, account, &Limits::default())?;
            Some((parsed, run, now))
        }
        [word, tenant, account, run, now, count, prefix, flags @ ..] if word == "bulk" => {
            let items = bulk_findings(account, count.parse()?, prefix, flags.iter().any(|flag| flag == "nul"));
            Some((findings_of(tenant, account, items)?, run, now))
        }
        [word, tenant, account, run, now] if word == "twin" => {
            let items = ["one", "two"]
                .iter()
                .map(|name| finding_of(account, "same-uid".to_owned(), format!("res-{name}"), Status::Fail, Severity::High))
                .collect();
            Some((findings_of(tenant, account, items)?, run, now))
        }
        _ => Err(Box::<dyn Error>::from(USAGE))?,
    };
    if let Some((findings, run, now)) = prepared {
        let scope = findings.tenant.clone();
        let outcome = replace_run(&exec, &scope, &findings, run, now.parse()?).await;
        writeln!(stdout(), "{outcome:?}")?;
    }
    Ok(())
}


fn main() -> Result<ExitCode, Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((settings, words)) => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            match runtime.block_on(scenario(Path::new(settings), words)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => Ok(writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE)?),
            }
        }
        None => Ok(writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE)?),
    }
}
