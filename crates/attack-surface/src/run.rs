use crate::command::naabu_args;
use crate::error::{RunError, ScanFailure};
use crate::model::{
    Found, Limits, Outcome, Report, ScanReport, Scope, ScopeKind, TargetReport, MAX_RUN_ADDRESSES_V4, MAX_RUN_ADDRESSES_V6, MAX_TARGET_PREFIX_V6,
};
use crate::results::parse_naabu;
use crate::scope::{address_count, check_range};
use crate::types::ScanResult;
use ipnet::IpNet;
use net_topology::runner::run_command;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;


pub enum Plan {
    Skip(Outcome),
    Scan(IpNet),
}


/// Decides alone what one target gets: refused by the checks, unproven ownership (external scope), too wide an IPv6 range, or a run.
pub fn plan_target(scope: &Scope, target: &str) -> Plan {
    match check_range(target, scope.kind) {
        Err(_) => Plan::Skip(Outcome::Failed(ScanFailure::Refused)),
        Ok(_) if scope.kind == ScopeKind::External && !scope.attested.iter().any(|listed| listed == target) => {
            Plan::Skip(Outcome::OwnershipUnverified)
        }
        Ok(net) if net.addr().is_ipv6() && net.prefix_len() < MAX_TARGET_PREFIX_V6 => Plan::Skip(Outcome::TooWide),
        Ok(net) => Plan::Scan(net),
    }
}


/// The addresses all runs of one scan cover, IPv4 and IPv6 apart; refused before any spawn when either is above its limit.
pub fn check_run_total(plans: &[Plan]) -> Result<(), RunError> {
    let (v4, v6) = plans.iter().fold((0u128, 0u128), |(sum_v4, sum_v6), plan| match plan {
        Plan::Scan(net @ IpNet::V4(_)) => (sum_v4 + address_count(net), sum_v6),
        Plan::Scan(net @ IpNet::V6(_)) => (sum_v4, sum_v6 + address_count(net)),
        Plan::Skip(_) => (sum_v4, sum_v6),
    });
    if v4 > MAX_RUN_ADDRESSES_V4 || v6 > MAX_RUN_ADDRESSES_V6 {
        Err(RunError::TooBroad {
            v4,
            v6,
            max_v4: MAX_RUN_ADDRESSES_V4,
            max_v6: MAX_RUN_ADDRESSES_V6,
        })
    } else {
        Ok(())
    }
}


/// One naabu run for one target: the argument vector of `naabu_args`, the capped and timed run, then the in-scope results.
pub fn run_target(program: &Path, scope: &Scope, limits: &Limits, deadline: Duration, target: &str) -> Result<Report, ScanFailure> {
    let arguments = naabu_args(scope, target).map_err(|_| ScanFailure::Refused)?;
    let texts = arguments
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let borrowed = texts.iter().map(String::as_str).collect::<Vec<_>>();
    let bytes = run_command(program, &borrowed, limits.max_bytes, deadline)?;
    Ok(parse_naabu(&mut bytes.as_slice(), scope, limits)?)
}


pub fn outcome_of(result: Result<Report, ScanFailure>) -> (Outcome, Vec<Found>) {
    match result {
        Ok(report) => (
            Outcome::Scanned {
                kept: report.found.len(),
                counts: report.counts,
            },
            report.found,
        ),
        Err(failure) => (Outcome::Failed(failure), Vec::new()),
    }
}


fn execute(program: &Path, scope: &Scope, limits: &Limits, deadline: Duration, target: &str, plan: Plan) -> (Outcome, Vec<Found>) {
    match plan {
        Plan::Skip(outcome) => (outcome, Vec::new()),
        Plan::Scan(_) => outcome_of(run_target(program, scope, limits, deadline, target)),
    }
}


/// Runs naabu once per target of a validated `scope` and keeps the in-scope open ports; a failing target is named by its index and the others still run.
pub fn scan_scope(program: &Path, scope: &Scope, limits: &Limits, deadline: Duration) -> ScanResult {
    let plans = scope.targets.iter().map(|target| plan_target(scope, target)).collect::<Vec<_>>();
    check_run_total(&plans)?;
    let done = scope
        .targets
        .iter()
        .zip(plans)
        .enumerate()
        .map(|(index, (target, plan))| (index, execute(program, scope, limits, deadline, target, plan)))
        .collect::<Vec<_>>();
    let found = done
        .iter()
        .flat_map(|(_, (_, kept))| kept.iter().map(|item| (item.ip, item.port)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(ip, port)| Found { ip, port })
        .collect();
    let targets = done.into_iter().map(|(index, (outcome, _))| TargetReport { index, outcome }).collect();
    Ok(ScanReport { found, targets })
}


/// One line: how many targets were scanned, left unproven, too wide or failed.
pub fn summary_line(report: &ScanReport) -> String {
    let count = |wanted: fn(&Outcome) -> bool| report.targets.iter().filter(|target| wanted(&target.outcome)).count();
    format!(
        "{} targets: {} scanned, {} ownership_unverified, {} too_wide, {} failed",
        report.targets.len(),
        count(|outcome| matches!(outcome, Outcome::Scanned { .. })),
        count(|outcome| matches!(outcome, Outcome::OwnershipUnverified)),
        count(|outcome| matches!(outcome, Outcome::TooWide)),
        count(|outcome| matches!(outcome, Outcome::Failed(_))),
    )
}
