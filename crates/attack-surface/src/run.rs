use crate::command::naabu_args;
use crate::error::{RunError, ScanFailure};
use crate::model::{
    AddressRun, Found, Limits, Outcome, Report, ScanReport, Scope, ScopeKind, SummaryCategory, TargetReport, MAX_ADDRESSES_PER_NAME,
    MAX_RESOLVE_SECONDS, MAX_RUN_ADDRESSES_V4, MAX_RUN_ADDRESSES_V6, MAX_TARGET_PREFIX_V6,
};
use crate::results::parse_naabu;
use crate::scope::{address_count, check_range};
use crate::text::valid_hostname;
use crate::types::{Executed, ResolveFn, ScanResult};
use ipnet::IpNet;
use net_topology::runner::run_command;
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};
use synthetic_checks::dns::dns_resolve;
use synthetic_checks::target::guard_address;


pub enum Plan {
    Skip(Outcome),
    Scan(IpNet),
    Resolve(String),
}


pub enum Ready {
    Skip(Outcome),
    Scan,
    Addresses { addresses: Vec<IpAddr>, refused: Vec<IpAddr> },
}


pub struct Phase {
    pub ready: Vec<Ready>,
    pub past: bool,
    pub v4: u128,
    pub v6: u128,
}


pub struct Resolver {
    pub nameserver: Option<SocketAddr>,
    pub resolve: ResolveFn,
}


pub struct Runner<'a> {
    pub program: &'a Path,
    pub scope: &'a Scope,
    pub limits: &'a Limits,
    pub deadline: Duration,
}


fn is_unattested(scope: &Scope, target: &str) -> bool {
    scope.kind == ScopeKind::External && !scope.attested.iter().any(|listed| listed == target)
}


fn plan_address(scope: &Scope, target: &str) -> Plan {
    match check_range(target, scope.kind) {
        Err(_) => Plan::Skip(Outcome::Failed(ScanFailure::Refused)),
        Ok(_) if is_unattested(scope, target) => Plan::Skip(Outcome::OwnershipUnverified),
        Ok(net) if net.addr().is_ipv6() && net.prefix_len() < MAX_TARGET_PREFIX_V6 => Plan::Skip(Outcome::TooWide),
        Ok(net) => Plan::Scan(net),
    }
}


/// Decides alone what one target gets: refused by the checks, unproven ownership (external scope), too wide an IPv6 range, a name to resolve, or a run.
pub fn plan_target(scope: &Scope, target: &str) -> Plan {
    match (
        check_range(target, scope.kind).is_err() && valid_hostname(target),
        is_unattested(scope, target),
    ) {
        (true, true) => Plan::Skip(Outcome::OwnershipUnverified),
        (true, false) => Plan::Resolve(target.to_string()),
        (false, _) => plan_address(scope, target),
    }
}


/// The IPv4 and IPv6 addresses the planned runs cover.
pub fn plan_totals(plans: &[Plan]) -> (u128, u128) {
    plans.iter().fold((0u128, 0u128), |(sum_v4, sum_v6), plan| match plan {
        Plan::Scan(net @ IpNet::V4(_)) => (sum_v4 + address_count(net), sum_v6),
        Plan::Scan(net @ IpNet::V6(_)) => (sum_v4, sum_v6 + address_count(net)),
        Plan::Skip(_) | Plan::Resolve(_) => (sum_v4, sum_v6),
    })
}


/// The addresses all runs of one scan cover, IPv4 and IPv6 apart; refused before any spawn when either is above its limit. Names count nothing here.
pub fn check_run_total(plans: &[Plan]) -> Result<(), RunError> {
    let (v4, v6) = plan_totals(plans);
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


/// A resolved address is scanned only when the class check of the scope kind and the synthetic-checks guard both accept it.
pub fn address_allowed(scope: &Scope, address: IpAddr) -> bool {
    let guard_ranges: &[IpNet] = match scope.kind {
        ScopeKind::Internal => &scope.ranges,
        ScopeKind::External => &[],
    };
    check_range(&IpNet::from(address).to_string(), scope.kind).is_ok() && guard_address(address, guard_ranges).is_ok()
}


fn canonical_unique(found: Vec<IpAddr>) -> Vec<IpAddr> {
    found
        .into_iter()
        .map(|address| address.to_canonical())
        .fold(Vec::new(), |mut seen, address| {
            if !seen.contains(&address) {
                seen.push(address);
            }
            seen
        })
}


fn checked_addresses(scope: &Scope, unique: Vec<IpAddr>) -> Ready {
    let (addresses, refused) = unique.into_iter().partition(|address| address_allowed(scope, *address));
    Ready::Addresses { addresses, refused }
}


/// One lookup of `name` (fully qualified): too many, none, a failure by kind only, or the checked addresses.
pub fn resolve_name(scope: &Scope, name: &str, resolver: &Resolver) -> Ready {
    let qualified = format!("{name}.");
    let left = Duration::from_secs(MAX_RESOLVE_SECONDS);
    let answer = (resolver.resolve)(resolver.nameserver, &qualified, left, MAX_ADDRESSES_PER_NAME + 1);
    match answer.map(canonical_unique) {
        Err(error) => Ready::Skip(Outcome::ResolveFailed { kind: error.kind() }),
        Ok(unique) if unique.is_empty() => Ready::Skip(Outcome::ResolveFailed { kind: ErrorKind::NotFound }),
        Ok(unique) if unique.len() > MAX_ADDRESSES_PER_NAME => Ready::Skip(Outcome::TooManyAddresses { max: MAX_ADDRESSES_PER_NAME }),
        Ok(unique) => checked_addresses(scope, unique),
    }
}


fn family_count(addresses: &[IpAddr], wanted: fn(&IpAddr) -> bool) -> u128 {
    addresses.iter().map(|address| u128::from(wanted(address))).sum()
}


/// A name whose checked addresses would push the run past a total is `OverBudget` alone; the others still run.
pub fn within_budget(ready: Ready, v4: u128, v6: u128) -> (Ready, u128, u128) {
    match ready {
        Ready::Addresses { addresses, refused } => {
            let more_v4 = v4 + family_count(&addresses, IpAddr::is_ipv4);
            let more_v6 = v6 + family_count(&addresses, IpAddr::is_ipv6);
            if more_v4 > MAX_RUN_ADDRESSES_V4 || more_v6 > MAX_RUN_ADDRESSES_V6 {
                (Ready::Skip(Outcome::OverBudget), v4, v6)
            } else {
                (Ready::Addresses { addresses, refused }, more_v4, more_v6)
            }
        }
        other => (other, v4, v6),
    }
}


fn resolve_step(scope: &Scope, resolver: &Resolver, expired: &dyn Fn() -> bool, state: Phase, plan: Plan) -> Phase {
    let (ready, past) = match plan {
        Plan::Skip(outcome) => (Ready::Skip(outcome), state.past),
        Plan::Scan(_) => (Ready::Scan, state.past),
        Plan::Resolve(name) => {
            let late = state.past || expired();
            let looked_up = if late {
                Ready::Skip(Outcome::Deferred)
            } else {
                resolve_name(scope, &name, resolver)
            };
            (looked_up, late)
        }
    };
    let (budgeted, v4, v6) = within_budget(ready, state.v4, state.v6);
    let mut all = state.ready;
    all.push(budgeted);
    Phase { ready: all, past, v4, v6 }
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


/// The scope of one resolved address: same kind, rate and ports, that address as the only target and range, and its `/32` or `/128` text.
pub fn address_scope(scope: &Scope, address: IpAddr) -> (Scope, String) {
    let net = IpNet::from(address);
    let text = net.to_string();
    let single = Scope {
        kind: scope.kind,
        rate_per_second: scope.rate_per_second,
        ports: scope.ports.clone(),
        ranges: vec![net],
        targets: vec![text.clone()],
        attested: vec![text.clone()],
    };
    (single, text)
}


fn report_of(index: usize, outcome: Outcome) -> TargetReport {
    TargetReport {
        index,
        outcome,
        runs: Vec::new(),
        refused_addresses: Vec::new(),
    }
}


fn run_addresses(runner: &Runner, addresses: Vec<IpAddr>, past: bool, expired: &dyn Fn() -> bool) -> (Vec<AddressRun>, Vec<Found>, bool) {
    addresses
        .into_iter()
        .fold((Vec::new(), Vec::new(), past), |(mut runs, mut found, behind), address| {
            let late = behind || expired();
            let (outcome, kept) = if late {
                (Outcome::Deferred, Vec::new())
            } else {
                let (single, text) = address_scope(runner.scope, address);
                outcome_of(run_target(runner.program, &single, runner.limits, runner.deadline, &text))
            };
            runs.push(AddressRun { address, outcome });
            found.extend(kept);
            (runs, found, late)
        })
}


fn execute(runner: &Runner, index: usize, target: &str, ready: Ready, past: bool, expired: &dyn Fn() -> bool) -> Executed {
    match ready {
        Ready::Skip(outcome) => (report_of(index, outcome), Vec::new(), past),
        Ready::Scan => {
            let late = past || expired();
            let (outcome, kept) = if late {
                (Outcome::Deferred, Vec::new())
            } else {
                outcome_of(run_target(runner.program, runner.scope, runner.limits, runner.deadline, target))
            };
            (report_of(index, outcome), kept, late)
        }
        Ready::Addresses { addresses, refused } => {
            let outcome = if addresses.is_empty() {
                Outcome::Failed(ScanFailure::Refused)
            } else {
                Outcome::Resolved { addresses: addresses.len() }
            };
            let (runs, kept, late) = run_addresses(runner, addresses, past, expired);
            let report = TargetReport {
                index,
                outcome,
                runs,
                refused_addresses: refused,
            };
            (report, kept, late)
        }
    }
}


/// Runs naabu once per target of a validated `scope`; once `total` has passed the targets left are `Outcome::Deferred`, never started.
pub fn scan_scope(program: &Path, scope: &Scope, limits: &Limits, deadline: Duration, total: Duration) -> ScanResult {
    let started = Instant::now();
    scan_scope_until(program, scope, limits, deadline, &|| started.elapsed() >= total)
}


/// `scan_scope` with the total deadline given as a check, asked before each lookup and run and never again once it answered true; names go to the system resolver.
pub fn scan_scope_until(program: &Path, scope: &Scope, limits: &Limits, deadline: Duration, expired: &dyn Fn() -> bool) -> ScanResult {
    let resolver = Resolver {
        nameserver: None,
        resolve: dns_resolve,
    };
    scan_scope_resolving(program, scope, limits, deadline, expired, &resolver)
}


/// The scan itself: every name is resolved once (in target order, before the first spawn), each address checked, budgeted, then run alone.
pub fn scan_scope_resolving(
    program: &Path,
    scope: &Scope,
    limits: &Limits,
    deadline: Duration,
    expired: &dyn Fn() -> bool,
    resolver: &Resolver,
) -> ScanResult {
    let plans = scope.targets.iter().map(|target| plan_target(scope, target)).collect::<Vec<_>>();
    check_run_total(&plans)?;
    let (v4, v6) = plan_totals(&plans);
    let start = Phase {
        ready: Vec::new(),
        past: false,
        v4,
        v6,
    };
    let resolved = plans
        .into_iter()
        .fold(start, |state, plan| resolve_step(scope, resolver, expired, state, plan));
    let runner = Runner {
        program,
        scope,
        limits,
        deadline,
    };
    let (done, _) =
        scope
            .targets
            .iter()
            .zip(resolved.ready)
            .enumerate()
            .fold((Vec::new(), resolved.past), |(mut reached, past), (index, (target, ready))| {
                let (report, kept, late) = execute(&runner, index, target, ready, past, expired);
                reached.push((report, kept));
                (reached, late)
            });
    let found = done
        .iter()
        .flat_map(|(_, kept)| kept.iter().map(|item| (item.ip, item.port)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(ip, port)| Found { ip, port })
        .collect();
    let targets = done.into_iter().map(|(report, _)| report).collect();
    Ok(ScanReport { found, targets })
}


/// The summary category of a target: every target lands in exactly one.
pub fn summary_category(target: &TargetReport) -> SummaryCategory {
    match &target.outcome {
        Outcome::Scanned { .. } => SummaryCategory::Scanned,
        Outcome::OwnershipUnverified => SummaryCategory::OwnershipUnverified,
        Outcome::TooWide => SummaryCategory::TooWide,
        Outcome::Deferred => SummaryCategory::Deferred,
        Outcome::Resolved { .. } if target.runs.iter().any(|run| matches!(run.outcome, Outcome::Scanned { .. })) => SummaryCategory::Scanned,
        Outcome::Resolved { .. } if target.runs.iter().all(|run| run.outcome == Outcome::Deferred) => SummaryCategory::Deferred,
        _ => SummaryCategory::Failed,
    }
}


/// One line: how many targets were scanned, left unproven, too wide, deferred or failed; the five counts add up to the targets.
pub fn summary_line(report: &ScanReport) -> String {
    let count = |wanted: SummaryCategory| report.targets.iter().filter(|target| summary_category(target) == wanted).count();
    format!(
        "{} targets: {} scanned, {} ownership_unverified, {} too_wide, {} deferred, {} failed",
        report.targets.len(),
        count(SummaryCategory::Scanned),
        count(SummaryCategory::OwnershipUnverified),
        count(SummaryCategory::TooWide),
        count(SummaryCategory::Deferred),
        count(SummaryCategory::Failed),
    )
}
