#![cfg(unix)]
use attack_surface::model::{
    AddressRun, Counts, Found, Limits, Outcome, ScanReport, Scope, TargetReport, MAX_ADDRESSES_PER_NAME, MAX_RESOLVE_SECONDS,
};
use attack_surface::run::{
    address_allowed, address_scope, check_run_total, plan_target, plan_totals, scan_scope_resolving, scan_scope_until, summary_line, within_budget,
    Plan, Ready, Resolver,
};
use attack_surface::scope::parse_scope;
use attack_surface::types::ResolveFn;
use dns_stub::{finish, serve, Mode, SOA_MARKER};
use std::cell::Cell;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use synthetic_checks::dns::dns_resolve;
use types::TestResult;


#[path = "support/dns_stub.rs"]
mod dns_stub;
#[path = "support/types.rs"]
mod types;


const SSH: u16 = 22;


const PAIR: usize = 2;


const TWO: usize = 2;


const THREE: usize = 3;


const EXIT_SEVEN: i32 = 7;


const SIXTEEN: u8 = 16;


const SEVENTEEN: u8 = 17;


const TWENTY: u8 = 20;


const PUBLIC_PREFIX: [u8; 3] = [8, 8, 8];


const FIVE: u8 = 5;


const GENEROUS_SECONDS: u64 = 60;


const NAMES: u8 = 17;


const TYPE_A: u16 = 1;


const TYPE_AAAA: u16 = 28;


const V6_PER_NAME: usize = 16;


const QUERIES_PER_LOOKUP: usize = 2;


fn generous() -> Duration {
    Duration::from_secs(GENEROUS_SECONDS)
}


fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}


fn missing() -> PathBuf {
    fixture("no-such-program")
}


fn scope_text(kind: &str, entries: &[(&str, &str)]) -> String {
    let targets = entries
        .iter()
        .map(|(value, method)| format!("  - value: {value}\n    ownership: {{method: {method}, reference: REF-1}}\n"))
        .collect::<String>();
    format!("kind: {kind}\nrate_per_second: 100\nports: [22]\ntargets:\n{targets}")
}


fn scope_of(kind: &str, entries: &[(&str, &str)]) -> Result<Scope, Box<dyn Error>> {
    let text = scope_text(kind, entries);
    let mut bytes = text.as_bytes();
    Ok(parse_scope(&mut bytes, "scope.yaml")?)
}


fn attested(kind: &str, values: &[&str]) -> Result<Scope, Box<dyn Error>> {
    let entries = values.iter().map(|value| (*value, "attestation")).collect::<Vec<_>>();
    scope_of(kind, &entries)
}


fn ips(texts: &[&str]) -> Vec<IpAddr> {
    texts.iter().filter_map(|text| text.parse().ok()).collect()
}


fn never(_: &str, _: usize) -> Mode {
    Mode::Empty
}


fn scan(scope: &Scope, program: &Path, nameserver: Option<SocketAddr>, resolve: ResolveFn) -> Result<ScanReport, Box<dyn Error>> {
    let resolver = Resolver { nameserver, resolve };
    Ok(scan_scope_resolving(
        program,
        scope,
        &Limits::default(),
        generous(),
        &|| false,
        &resolver,
    )?)
}


struct Stubbed {
    report: ScanReport,
    seen: Vec<(String, u16)>,
}


fn scan_stub(scope: &Scope, program: &Path, decide: fn(&str, usize) -> Mode) -> Result<Stubbed, Box<dyn Error>> {
    let stub = serve(decide)?;
    let report = scan(scope, program, Some(stub.address), dns_resolve)?;
    Ok(Stubbed { report, seen: finish(stub)? })
}


fn target(report: &ScanReport, index: usize) -> Result<&TargetReport, Box<dyn Error>> {
    Ok(report.targets.iter().find(|item| item.index == index).ok_or("no such target")?)
}


fn run_addresses(item: &TargetReport) -> Vec<IpAddr> {
    let mut found = item.runs.iter().map(|run| run.address).collect::<Vec<_>>();
    found.sort();
    found
}


fn queries_of(seen: &[(String, u16)], kind: u16) -> usize {
    seen.iter().filter(|(_, asked)| *asked == kind).count()
}


fn mixed_v4(_: &str, _: usize) -> Mode {
    Mode::Answers(ips(&["127.0.0.1", "10.0.0.1", "169.254.169.254", "8.8.8.8", "9.9.9.9"]))
}


fn mixed_v6(_: &str, _: usize) -> Mode {
    Mode::Answers(ips(&[
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "2606:4700::1111",
        "2606:4700::1112",
    ]))
}


fn public(count: u8, repeated: u8) -> Mode {
    let [first, second, third] = PUBLIC_PREFIX;
    let distinct = (1..=count).map(|last| IpAddr::V4(Ipv4Addr::new(first, second, third, last)));
    let again = (1..=repeated).map(|last| IpAddr::V4(Ipv4Addr::new(first, second, third, last)));
    Mode::Answers(distinct.chain(again).collect())
}


fn seventeen(_: &str, _: usize) -> Mode {
    public(SEVENTEEN, 0)
}


fn twenty(_: &str, _: usize) -> Mode {
    public(TWENTY, 0)
}


fn sixteen(_: &str, _: usize) -> Mode {
    public(SIXTEEN, 0)
}


fn sixteen_and_a_repeat(_: &str, _: usize) -> Mode {
    public(SIXTEEN, 1)
}


fn nxdomain(_: &str, _: usize) -> Mode {
    Mode::NxDomain
}


fn search_only(name: &str, _: usize) -> Mode {
    if name.ends_with(".search.test") {
        Mode::Answers(ips(&["8.8.8.8"]))
    } else {
        Mode::NxDomain
    }
}


fn changing(_: &str, index: usize) -> Mode {
    Mode::Answers(ips(&[if index < QUERIES_PER_LOOKUP { "8.8.8.8" } else { "9.9.9.9" }]))
}


fn single(_: &str, _: usize) -> Mode {
    Mode::Answers(ips(&["8.8.8.8"]))
}


fn fake_mixed(_: Option<SocketAddr>, _: &str, _: Duration, _: usize) -> std::io::Result<Vec<IpAddr>> {
    Ok(ips(&["10.1.0.7", "10.9.9.9", "8.8.8.8", "fd00:ec2::254", "fd00:ec2::7"]))
}


fn fake_metadata(_: Option<SocketAddr>, _: &str, _: Duration, _: usize) -> std::io::Result<Vec<IpAddr>> {
    Ok(ips(&["168.63.129.16", "8.8.8.8"]))
}


fn fake_private(_: Option<SocketAddr>, _: &str, _: Duration, _: usize) -> std::io::Result<Vec<IpAddr>> {
    Ok(ips(&["10.1.0.5"]))
}


fn fake_timed_out(_: Option<SocketAddr>, _: &str, _: Duration, _: usize) -> std::io::Result<Vec<IpAddr>> {
    Err(IoError::new(ErrorKind::TimedOut, "TIMEOUT-MARKER"))
}


fn fake_empty(_: Option<SocketAddr>, _: &str, _: Duration, _: usize) -> std::io::Result<Vec<IpAddr>> {
    Ok(Vec::new())
}


fn fake_sixteen_v6(_: Option<SocketAddr>, _: &str, _: Duration, _: usize) -> std::io::Result<Vec<IpAddr>> {
    let names = (1..=V6_PER_NAME).map(|last| format!("2606:4700::{last:x}")).collect::<Vec<_>>();
    Ok(names.iter().filter_map(|text| text.parse().ok()).collect())
}


fn fake_arguments(nameserver: Option<SocketAddr>, name: &str, left: Duration, cap: usize) -> std::io::Result<Vec<IpAddr>> {
    let seconds = u8::try_from(left.as_secs()).map_err(IoError::other)?;
    let capped = u8::try_from(cap).map_err(IoError::other)?;
    if nameserver.is_some() && name == "args.example." {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(PUBLIC_PREFIX[0], PUBLIC_PREFIX[1], seconds, capped))])
    } else {
        Err(IoError::from(ErrorKind::InvalidInput))
    }
}


#[test]
fn each_answer_is_checked_alone_and_the_public_ones_of_the_same_answer_are_scanned() -> TestResult {
    let scope = attested("external", &["Scan.Example.com"])?;
    let Stubbed { report, seen } = scan_stub(&scope, &fixture("ok.sh"), mixed_v4)?;
    let item = target(&report, 0)?;
    assert_eq!(item.outcome, Outcome::Resolved { addresses: PAIR });
    let mut refused = item.refused_addresses.clone();
    refused.sort();
    assert_eq!(refused, ips(&["10.0.0.1", "127.0.0.1", "169.254.169.254"]));
    assert_eq!(run_addresses(item), ips(&["8.8.8.8", "9.9.9.9"]));
    assert_eq!(
        report.found,
        vec![
            Found {
                ip: "8.8.8.8".parse()?,
                port: SSH
            },
            Found {
                ip: "9.9.9.9".parse()?,
                port: SSH
            }
        ]
    );
    assert!(seen.iter().all(|(name, _)| name == "scan.example.com"), "{seen:?}");
    assert_eq!(queries_of(&seen, TYPE_A), 1);
    Ok(())
}


#[test]
fn mapped_nat64_and_teredo_answers_are_refused_alone() -> TestResult {
    let scope = attested("external", &["v6.example.com"])?;
    let Stubbed { report, .. } = scan_stub(&scope, &missing(), mixed_v6)?;
    let item = target(&report, 0)?;
    let mut refused = item.refused_addresses.clone();
    refused.sort();
    let mut expected = ips(&["10.0.0.1", "64:ff9b::a00:1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"]);
    expected.sort();
    assert_eq!(refused, expected);
    assert_eq!(run_addresses(item), ips(&["2606:4700::1111", "2606:4700::1112"]));
    assert!(item.runs.iter().all(|run| matches!(run.outcome, Outcome::Failed(_))));
    Ok(())
}


#[test]
fn seventeen_distinct_addresses_scan_nothing_and_sixteen_are_all_checked() -> TestResult {
    let scope = attested("external", &["many.example.com"])?;
    [seventeen, twenty].into_iter().try_for_each(|decide| -> TestResult {
        let Stubbed { report, .. } = scan_stub(&scope, &missing(), decide)?;
        let item = target(&report, 0)?;
        assert_eq!(item.outcome, Outcome::TooManyAddresses { max: MAX_ADDRESSES_PER_NAME });
        assert!(item.runs.is_empty());
        assert!(item.refused_addresses.is_empty());
        Ok(())
    })?;
    [sixteen, sixteen_and_a_repeat].into_iter().try_for_each(|decide| -> TestResult {
        let Stubbed { report, .. } = scan_stub(&scope, &missing(), decide)?;
        let item = target(&report, 0)?;
        assert_eq!(
            item.outcome,
            Outcome::Resolved {
                addresses: MAX_ADDRESSES_PER_NAME
            }
        );
        assert_eq!(item.runs.len(), MAX_ADDRESSES_PER_NAME);
        Ok(())
    })
}


#[test]
fn an_nxdomain_soa_marker_reaches_no_text_of_the_report() -> TestResult {
    let scope = attested("external", &["gone.example.com"])?;
    let Stubbed { report, .. } = scan_stub(&scope, &missing(), nxdomain)?;
    let item = target(&report, 0)?;
    assert!(matches!(item.outcome, Outcome::ResolveFailed { .. }));
    assert!(!format!("{report:?}").contains(SOA_MARKER));
    assert!(!summary_line(&report).contains(SOA_MARKER));
    Ok(())
}


#[test]
fn an_empty_answer_is_a_named_failure() -> TestResult {
    let scope = attested("external", &["empty.example.com"])?;
    let Stubbed { report, .. } = scan_stub(&scope, &missing(), never)?;
    assert!(matches!(target(&report, 0)?.outcome, Outcome::ResolveFailed { .. }));
    let direct = scan(&scope, &missing(), None, fake_empty)?;
    assert_eq!(target(&direct, 0)?.outcome, Outcome::ResolveFailed { kind: ErrorKind::NotFound });
    Ok(())
}


#[test]
fn the_search_domain_is_never_used() -> TestResult {
    let scope = attested("external", &["x.example"])?;
    let Stubbed { report, seen } = scan_stub(&scope, &missing(), search_only)?;
    assert!(matches!(target(&report, 0)?.outcome, Outcome::ResolveFailed { .. }));
    assert!(seen.iter().all(|(name, _)| name == "x.example"), "{seen:?}");
    Ok(())
}


#[test]
fn a_changing_answer_is_looked_up_once_and_naabu_sees_the_first_one() -> TestResult {
    let scope = attested("external", &["Flip.example.com", "flip.example.com"])?;
    assert_eq!(scope.targets.len(), 1);
    let Stubbed { report, seen } = scan_stub(&scope, &fixture("ok.sh"), changing)?;
    assert_eq!(run_addresses(target(&report, 0)?), ips(&["8.8.8.8"]), "{seen:?}");
    assert_eq!(queries_of(&seen, TYPE_A), 1);
    assert_eq!(queries_of(&seen, TYPE_AAAA), 1);
    assert_eq!(
        report.found,
        vec![Found {
            ip: "8.8.8.8".parse()?,
            port: SSH
        }]
    );
    Ok(())
}


#[test]
fn naabu_gets_the_address_and_never_the_name() -> TestResult {
    let scope = attested("external", &["named.example.com"])?;
    let Stubbed { report, .. } = scan_stub(&scope, &fixture("addr.sh"), single)?;
    let item = target(&report, 0)?;
    let run = item.runs.first().ok_or("no run")?;
    assert_eq!(run.address, "8.8.8.8".parse::<IpAddr>()?);
    assert!(matches!(run.outcome, Outcome::Scanned { kept: 1, .. }), "{:?}", run.outcome);
    let named = Outcome::Failed(attack_surface::error::ScanFailure::Failed { code: Some(EXIT_SEVEN) });
    assert_ne!(run.outcome, named);
    Ok(())
}


#[test]
fn a_lookup_gets_a_qualified_name_the_deadline_and_one_more_than_the_cap() -> TestResult {
    let scope = attested("external", &["args.example"])?;
    let nameserver = Some("127.0.0.1:9".parse::<SocketAddr>()?);
    let report = scan(&scope, &missing(), nameserver, fake_arguments)?;
    let expected = IpAddr::V4(Ipv4Addr::new(
        PUBLIC_PREFIX[0],
        PUBLIC_PREFIX[1],
        u8::try_from(MAX_RESOLVE_SECONDS)?,
        SEVENTEEN,
    ));
    assert_eq!(run_addresses(target(&report, 0)?), vec![expected]);
    assert_eq!(MAX_ADDRESSES_PER_NAME + 1, usize::from(SEVENTEEN));
    assert_eq!(MAX_RESOLVE_SECONDS, u64::from(FIVE));
    Ok(())
}


#[test]
fn a_timed_out_lookup_is_named_by_kind_and_the_other_targets_still_run() -> TestResult {
    let scope = attested("external", &["9.9.9.0/24", "slow.example.com"])?;
    let report = scan(&scope, &fixture("ok.sh"), None, fake_timed_out)?;
    assert!(matches!(target(&report, 0)?.outcome, Outcome::Scanned { kept: 1, .. }));
    let slow = target(&report, 1)?;
    assert_eq!(slow.outcome, Outcome::ResolveFailed { kind: ErrorKind::TimedOut });
    assert!(!format!("{report:?}").contains("TIMEOUT-MARKER"));
    assert_eq!(
        summary_line(&report),
        "2 targets: 1 scanned, 0 ownership_unverified, 0 too_wide, 0 deferred, 1 failed"
    );
    Ok(())
}


#[test]
fn once_the_total_has_passed_no_name_is_looked_up_and_nothing_is_started() -> TestResult {
    let scope = attested("external", &["8.8.8.0/24", "a.example", "b.example", "c.example"])?;
    let calls = Cell::new(0usize);
    let stub = serve(single)?;
    let resolver = Resolver {
        nameserver: Some(stub.address),
        resolve: dns_resolve,
    };
    let report = scan_scope_resolving(
        &missing(),
        &scope,
        &Limits::default(),
        generous(),
        &|| calls.replace(calls.get() + 1) >= 1,
        &resolver,
    )?;
    let seen = finish(stub)?;
    assert_eq!(report.targets.len(), scope.targets.len());
    assert_eq!(target(&report, 0)?.outcome, Outcome::Deferred);
    assert_eq!(target(&report, 1)?.outcome, Outcome::Resolved { addresses: 1 });
    assert_eq!(
        target(&report, 1)?.runs,
        vec![AddressRun {
            address: "8.8.8.8".parse()?,
            outcome: Outcome::Deferred
        }]
    );
    assert_eq!(target(&report, TWO)?.outcome, Outcome::Deferred);
    assert_eq!(target(&report, THREE)?.outcome, Outcome::Deferred);
    assert!(seen.iter().all(|(name, _)| name == "a.example"), "{seen:?}");
    Ok(())
}


#[test]
fn the_scan_until_entry_point_resolves_through_the_system_configuration() -> TestResult {
    let scope = attested("external", &["8.8.8.0/24"])?;
    let report = scan_scope_until(&fixture("ok.sh"), &scope, &Limits::default(), generous(), &|| false)?;
    assert!(matches!(target(&report, 0)?.outcome, Outcome::Scanned { .. }));
    Ok(())
}


#[test]
fn seventeen_names_of_sixteen_ipv6_addresses_overrun_the_budget_on_the_last_one_only() -> TestResult {
    let values = (1..=NAMES).map(|number| format!("n{number:02}.example.com")).collect::<Vec<_>>();
    let borrowed = values.iter().map(String::as_str).collect::<Vec<_>>();
    let scope = attested("external", &borrowed)?;
    let report = scan(&scope, &missing(), None, fake_sixteen_v6)?;
    assert_eq!(report.targets.len(), usize::from(NAMES));
    let outcomes = report.targets.iter().map(|item| item.outcome.clone()).collect::<Vec<_>>();
    let resolved = Outcome::Resolved { addresses: V6_PER_NAME };
    assert!(
        outcomes.iter().take(usize::from(NAMES) - 1).all(|outcome| *outcome == resolved),
        "{outcomes:?}"
    );
    assert_eq!(outcomes.last(), Some(&Outcome::OverBudget));
    assert!(target(&report, usize::from(NAMES) - 1)?.runs.is_empty());
    Ok(())
}


#[test]
fn a_name_over_the_ipv4_budget_is_over_budget_and_the_address_target_still_runs() -> TestResult {
    let scope = attested("internal", &["10.1.0.0/16", "full.example.com"])?;
    let report = scan(&scope, &fixture("ok.sh"), None, fake_private)?;
    assert!(matches!(target(&report, 0)?.outcome, Outcome::Scanned { .. }));
    assert_eq!(target(&report, 1)?.outcome, Outcome::OverBudget);
    assert_eq!(
        summary_line(&report),
        "2 targets: 1 scanned, 0 ownership_unverified, 0 too_wide, 0 deferred, 1 failed"
    );
    Ok(())
}


#[test]
fn an_answer_never_makes_the_run_too_broad() -> TestResult {
    let scope = attested("internal", &["10.1.0.0/16", "a.example.com", "b.example.com"])?;
    assert!(scan(&scope, &missing(), None, fake_private).is_ok());
    let plans = vec![Plan::Resolve("a.example.com".to_string()), Plan::Skip(Outcome::TooWide)];
    assert!(check_run_total(&plans).is_ok());
    assert_eq!(plan_totals(&plans), (0, 0));
    Ok(())
}


#[test]
fn an_internal_answer_must_lie_in_the_opted_in_ranges_and_metadata_is_never_scoped() -> TestResult {
    let scope = attested("internal", &["10.1.0.0/24", "fd00:ec2::/48", "inner.example.com"])?;
    let report = scan(&scope, &missing(), None, fake_mixed)?;
    let item = target(&report, TWO)?;
    assert_eq!(item.refused_addresses, ips(&["10.9.9.9", "8.8.8.8", "fd00:ec2::254"]));
    assert_eq!(
        item.runs.iter().map(|run| run.address).collect::<Vec<_>>(),
        ips(&["10.1.0.7", "fd00:ec2::7"])
    );
    Ok(())
}


#[test]
fn an_internal_scope_without_an_address_target_refuses_every_answer() -> TestResult {
    let scope = attested("internal", &["inner.example.com"])?;
    let report = scan(&scope, &missing(), None, fake_private)?;
    let item = target(&report, 0)?;
    assert_eq!(item.outcome, Outcome::Failed(attack_surface::error::ScanFailure::Refused));
    assert_eq!(item.refused_addresses, ips(&["10.1.0.5"]));
    assert!(item.runs.is_empty());
    Ok(())
}


#[test]
fn a_cloud_metadata_address_is_refused_in_an_external_scope() -> TestResult {
    let scope = attested("external", &["cloud.example.com"])?;
    let report = scan(&scope, &missing(), None, fake_metadata)?;
    let item = target(&report, 0)?;
    assert_eq!(item.refused_addresses, ips(&["168.63.129.16"]));
    assert_eq!(run_addresses(item), ips(&["8.8.8.8"]));
    Ok(())
}


#[test]
fn a_name_attested_in_another_spelling_is_unverified_and_never_looked_up() -> TestResult {
    let scope = scope_of("external", &[("Example.com", "dns_txt"), ("example.com", "attestation")])?;
    let Stubbed { report, seen } = scan_stub(&scope, &missing(), single)?;
    let item = target(&report, 0)?;
    assert_eq!(item.outcome, Outcome::OwnershipUnverified);
    assert!(seen.is_empty(), "{seen:?}");
    Ok(())
}


#[test]
fn plan_target_sorts_names_addresses_and_refusals() -> TestResult {
    let internal = attested("internal", &["10.1.0.0/24"])?;
    assert!(matches!(plan_target(&internal, "scan.example.com"), Plan::Resolve(name) if name == "scan.example.com"));
    assert!(matches!(plan_target(&internal, "-x.example.com"), Plan::Skip(Outcome::Failed(_))));
    assert!(matches!(plan_target(&internal, "8.8.8.8"), Plan::Skip(Outcome::Failed(_))));
    assert!(matches!(plan_target(&internal, "10.1.0.0/24"), Plan::Scan(_)));
    let external = scope_of("external", &[("8.8.8.0/24", "attestation")])?;
    assert!(matches!(
        plan_target(&external, "scan.example.com"),
        Plan::Skip(Outcome::OwnershipUnverified)
    ));
    Ok(())
}


#[test]
fn the_one_address_scope_keeps_kind_rate_and_ports_and_widens_nothing() -> TestResult {
    let scope = attested("external", &["8.8.8.0/24"])?;
    let (single_scope, text) = address_scope(&scope, "8.8.8.8".parse()?);
    assert_eq!(text, "8.8.8.8/32");
    assert_eq!(single_scope.targets, vec!["8.8.8.8/32"]);
    assert_eq!(single_scope.attested, vec!["8.8.8.8/32"]);
    assert_eq!(single_scope.ranges.len(), 1);
    assert_eq!(single_scope.kind, scope.kind);
    assert_eq!(single_scope.rate_per_second, scope.rate_per_second);
    assert_eq!(single_scope.ports, scope.ports);
    let (v6_scope, v6_text) = address_scope(&scope, "2606:4700::1111".parse()?);
    assert_eq!(v6_text, "2606:4700::1111/128");
    assert_eq!(v6_scope.targets, vec![v6_text]);
    assert!(address_allowed(&scope, "9.9.9.9".parse()?));
    assert!(!address_allowed(&scope, "127.0.0.1".parse()?));
    Ok(())
}


#[test]
fn the_budget_passes_a_skip_through_unchanged() -> TestResult {
    let (ready, v4, v6) = within_budget(Ready::Skip(Outcome::TooWide), 1, 1);
    assert!(matches!(ready, Ready::Skip(Outcome::TooWide)));
    assert_eq!((v4, v6), (1, 1));
    Ok(())
}


#[test]
fn the_summary_counts_the_name_outcomes() -> TestResult {
    let outcomes = [
        Outcome::Resolved { addresses: 1 },
        Outcome::ResolveFailed { kind: ErrorKind::Other },
        Outcome::TooManyAddresses { max: MAX_ADDRESSES_PER_NAME },
        Outcome::OverBudget,
        Outcome::Deferred,
        Outcome::Scanned {
            kept: 0,
            counts: Counts::default(),
        },
    ];
    let report = ScanReport {
        found: Vec::new(),
        targets: outcomes
            .into_iter()
            .enumerate()
            .map(|(index, outcome)| TargetReport {
                index,
                outcome,
                runs: Vec::new(),
                refused_addresses: Vec::new(),
            })
            .collect(),
    };
    assert_eq!(
        summary_line(&report),
        "6 targets: 2 scanned, 0 ownership_unverified, 0 too_wide, 1 deferred, 3 failed"
    );
    Ok(())
}
