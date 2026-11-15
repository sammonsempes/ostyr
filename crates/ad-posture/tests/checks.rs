use ad_posture::checks::{
    assess, check_group_size, check_inactive, check_kerberoastable, check_krbtgt_age, check_no_preauth, check_unconstrained_delegation, group_keys,
    is_privileged_sid, member_counts, privileged_groups, score_of, PENALTY_CRITICAL, PENALTY_HIGH, PENALTY_LOW, PENALTY_MEDIUM, SCORE_MAX,
    SECONDS_PER_DAY, UAC_DISABLED, UAC_DONT_REQ_PREAUTH, UAC_SERVER_TRUST, UAC_TRUSTED_FOR_DELEGATION,
};
use ad_posture::model::{Check, Entry, Finding, Severity, Snapshot, Thresholds};
use ad_posture::report::{format_finding, format_report};
use std::error::Error;


const NOW: i64 = 1_700_000_000;


const DAYS: i64 = SECONDS_PER_DAY;


const LIMIT_DAYS: u32 = 180;


const INACTIVE_DAYS: u32 = 90;


const MAX_MEMBERS: usize = 2;


const UAC_NORMAL: u32 = 512;


const UAC_KRBTGT: u32 = 514;


const MANY_FINDINGS: usize = 10;


const ADMINS_SID: &str = "S-1-5-21-1-2-3-512";


const DOMAIN_ADMINS: &str = "CN=Domain Admins,CN=Users,DC=x";


fn thresholds() -> Thresholds {
    Thresholds {
        krbtgt_max_age_days: LIMIT_DAYS,
        privileged_max_members: MAX_MEMBERS,
        inactive_days: INACTIVE_DAYS,
    }
}


fn entry(dn: &str, classes: &[&str], uac: u32) -> Entry {
    Entry {
        dn: dn.to_owned(),
        classes: classes.iter().map(|class| (*class).to_owned()).collect(),
        account: None,
        uac,
        spns: Vec::new(),
        member_of: Vec::new(),
        pwd_last_set: None,
        last_logon: None,
        sid: None,
    }
}


fn user(dn: &str, uac: u32) -> Entry {
    entry(dn, &["top", "person", "user"], uac)
}


fn with_spn(base: Entry) -> Entry {
    Entry {
        spns: vec!["http/web.x".to_owned()],
        ..base
    }
}


fn group(dn: &str, sid: Option<&str>) -> Entry {
    Entry {
        sid: sid.map(str::to_owned),
        ..entry(dn, &["top", "group"], 0)
    }
}


fn member(dn: &str, groups: &[&str], last_logon: Option<i64>) -> Entry {
    Entry {
        member_of: groups.iter().map(|name| (*name).to_owned()).collect(),
        last_logon,
        ..user(dn, UAC_NORMAL)
    }
}


fn krbtgt(changed: Option<i64>) -> Entry {
    Entry {
        account: Some("krbtgt".to_owned()),
        pwd_last_set: changed,
        ..user("CN=krbtgt,CN=Users,DC=x", UAC_KRBTGT)
    }
}


fn days_ago(days: i64) -> Option<i64> {
    Some(NOW - days * DAYS)
}


fn found(result: Option<Finding>) -> Result<Finding, Box<dyn Error>> {
    Ok(result.ok_or("no finding")?)
}


#[test]
fn an_enabled_user_with_an_spn_is_kerberoastable() -> Result<(), Box<dyn Error>> {
    let finding = found(check_kerberoastable(&with_spn(user("CN=svc,DC=x", UAC_NORMAL))))?;
    assert_eq!(finding.check, Check::Kerberoastable);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.object, "CN=svc,DC=x");
    assert!(!finding.reason.is_empty() && !finding.fix.is_empty());
    Ok(())
}


#[test]
fn a_computer_with_an_spn_is_not_kerberoastable() -> Result<(), Box<dyn Error>> {
    let computer = with_spn(entry("CN=pc,DC=x", &["top", "person", "user", "computer"], UAC_NORMAL));
    assert!(check_kerberoastable(&computer).is_none());
    let upper = with_spn(entry("CN=pc,DC=x", &["USER", "Computer"], UAC_NORMAL));
    assert!(check_kerberoastable(&upper).is_none());
    Ok(())
}


#[test]
fn a_user_without_spn_or_disabled_or_not_a_user_is_not_kerberoastable() -> Result<(), Box<dyn Error>> {
    assert!(check_kerberoastable(&user("CN=a,DC=x", UAC_NORMAL)).is_none());
    assert!(check_kerberoastable(&with_spn(user("CN=a,DC=x", UAC_NORMAL | UAC_DISABLED))).is_none());
    assert!(check_kerberoastable(&with_spn(entry("CN=g,DC=x", &["group"], 0))).is_none());
    assert!(check_kerberoastable(&with_spn(user("CN=a,DC=x", UAC_NORMAL))).is_some());
    Ok(())
}


#[test]
fn a_user_without_preauthentication_is_reported_only_when_enabled() -> Result<(), Box<dyn Error>> {
    let finding = found(check_no_preauth(&user("CN=a,DC=x", UAC_NORMAL | UAC_DONT_REQ_PREAUTH)))?;
    assert_eq!(finding.check, Check::NoPreauth);
    assert_eq!(finding.severity, Severity::High);
    assert!(check_no_preauth(&user("CN=a,DC=x", UAC_NORMAL | UAC_DONT_REQ_PREAUTH | UAC_DISABLED)).is_none());
    assert!(check_no_preauth(&user("CN=a,DC=x", UAC_NORMAL)).is_none());
    Ok(())
}


#[test]
fn unconstrained_delegation_is_reported_except_on_a_domain_controller() -> Result<(), Box<dyn Error>> {
    let computer = entry("CN=srv,DC=x", &["computer"], UAC_NORMAL | UAC_TRUSTED_FOR_DELEGATION);
    let finding = found(check_unconstrained_delegation(&computer))?;
    assert_eq!(finding.check, Check::UnconstrainedDelegation);
    let controller = entry("CN=dc,DC=x", &["computer"], UAC_SERVER_TRUST | UAC_TRUSTED_FOR_DELEGATION);
    assert!(check_unconstrained_delegation(&controller).is_none());
    let disabled = entry("CN=srv,DC=x", &["computer"], UAC_TRUSTED_FOR_DELEGATION | UAC_DISABLED);
    assert!(check_unconstrained_delegation(&disabled).is_none());
    assert!(check_unconstrained_delegation(&user("CN=a,DC=x", UAC_NORMAL)).is_none());
    Ok(())
}


#[test]
fn an_old_or_unrecorded_krbtgt_password_is_critical() -> Result<(), Box<dyn Error>> {
    let old = found(check_krbtgt_age(&krbtgt(days_ago(i64::from(LIMIT_DAYS) + 1)), &thresholds(), NOW))?;
    assert_eq!(old.check, Check::KrbtgtPasswordAge);
    assert_eq!(old.severity, Severity::Critical);
    assert!(check_krbtgt_age(&krbtgt(None), &thresholds(), NOW).is_some());
    Ok(())
}


#[test]
fn a_recent_krbtgt_password_and_other_accounts_are_not_reported() -> Result<(), Box<dyn Error>> {
    assert!(check_krbtgt_age(&krbtgt(days_ago(i64::from(LIMIT_DAYS))), &thresholds(), NOW).is_none());
    assert!(check_krbtgt_age(&krbtgt(Some(NOW + DAYS)), &thresholds(), NOW).is_none());
    let renamed = Entry {
        account: Some("admin".to_owned()),
        pwd_last_set: None,
        ..krbtgt(None)
    };
    assert!(check_krbtgt_age(&renamed, &thresholds(), NOW).is_none());
    let nameless = Entry {
        account: None,
        ..krbtgt(None)
    };
    assert!(check_krbtgt_age(&nameless, &thresholds(), NOW).is_none());
    let upper = Entry {
        account: Some("KRBTGT".to_owned()),
        ..krbtgt(None)
    };
    assert!(check_krbtgt_age(&upper, &thresholds(), NOW).is_some());
    Ok(())
}


#[test]
fn only_the_well_known_sids_are_privileged() -> Result<(), Box<dyn Error>> {
    assert!(is_privileged_sid("S-1-5-32-544"));
    assert!(is_privileged_sid("S-1-5-21-1-2-3-512"));
    assert!(is_privileged_sid("S-1-5-21-1-2-3-518"));
    assert!(is_privileged_sid("S-1-5-21-1-2-3-519"));
    assert!(!is_privileged_sid("S-1-5-21-1-2-3-513"));
    assert!(!is_privileged_sid("S-1-5-21-1-2-3-1512"));
    assert!(!is_privileged_sid("S-1-5-5-512"));
    assert!(!is_privileged_sid("S-1-5-32-545"));
    Ok(())
}


#[test]
fn a_group_is_privileged_by_its_sid_never_by_its_name() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        entries: vec![
            group(DOMAIN_ADMINS, Some(ADMINS_SID)),
            group("CN=Domain Admins,OU=Fake,DC=x", Some("S-1-5-21-1-2-3-1200")),
            group("CN=NoSid,DC=x", None),
            Entry {
                sid: Some(ADMINS_SID.to_owned()),
                ..user("CN=notagroup,DC=x", UAC_NORMAL)
            },
        ],
    };
    let groups = privileged_groups(&snapshot);
    assert_eq!(groups.iter().map(|entry| entry.dn.as_str()).collect::<Vec<_>>(), vec![DOMAIN_ADMINS]);
    Ok(())
}


#[test]
fn members_are_counted_once_per_group() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        entries: vec![
            group(DOMAIN_ADMINS, Some(ADMINS_SID)),
            member("CN=a,DC=x", &[DOMAIN_ADMINS, "cn=domain admins,cn=users,dc=X"], None),
            member("CN=b,DC=x", &["CN=Other,DC=x"], None),
            member("CN=c,DC=x", &[DOMAIN_ADMINS], None),
        ],
    };
    let keys = group_keys(&privileged_groups(&snapshot));
    let counts = member_counts(&snapshot, &keys);
    assert_eq!(counts.get(&DOMAIN_ADMINS.to_lowercase()), Some(&MAX_MEMBERS));
    assert_eq!(counts.len(), 1);
    Ok(())
}


#[test]
fn a_group_above_the_member_threshold_is_reported() -> Result<(), Box<dyn Error>> {
    let mut entries = vec![group(DOMAIN_ADMINS, Some(ADMINS_SID))];
    entries.extend(
        ["a", "b"]
            .iter()
            .map(|name| member(&format!("CN={name},DC=x"), &[DOMAIN_ADMINS], days_ago(1))),
    );
    let at_limit = Snapshot { entries: entries.clone() };
    let report = assess(&at_limit, &thresholds(), NOW);
    assert!(report.findings.is_empty());
    assert_eq!(report.score, SCORE_MAX);
    entries.push(member("CN=c,DC=x", &[DOMAIN_ADMINS], days_ago(1)));
    let above = Snapshot { entries };
    let report_above = assess(&above, &thresholds(), NOW);
    let finding = report_above.findings.first().ok_or("no finding")?;
    assert_eq!(finding.check, Check::PrivilegedGroupSize);
    assert_eq!(finding.object, DOMAIN_ADMINS);
    assert_eq!(report_above.findings.len(), 1);
    let keys = group_keys(&privileged_groups(&above));
    let empty = Snapshot {
        entries: vec![group(DOMAIN_ADMINS, Some(ADMINS_SID))],
    };
    let empty_group = empty.entries.first().ok_or("no group")?;
    assert!(check_group_size(empty_group, &member_counts(&empty, &keys), &thresholds()).is_none());
    Ok(())
}


#[test]
fn an_inactive_privileged_user_is_reported() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        entries: vec![group(DOMAIN_ADMINS, Some(ADMINS_SID))],
    };
    let keys = group_keys(&privileged_groups(&snapshot));
    let never = member("CN=never,DC=x", &[DOMAIN_ADMINS], None);
    let finding = found(check_inactive(&never, &keys, &thresholds(), NOW))?;
    assert_eq!(finding.check, Check::InactivePrivileged);
    assert_eq!(finding.severity, Severity::Medium);
    let stale = member("CN=stale,DC=x", &[DOMAIN_ADMINS], days_ago(i64::from(INACTIVE_DAYS) + 1));
    assert!(check_inactive(&stale, &keys, &thresholds(), NOW).is_some());
    let edge = member("CN=edge,DC=x", &[DOMAIN_ADMINS], days_ago(i64::from(INACTIVE_DAYS)));
    assert!(check_inactive(&edge, &keys, &thresholds(), NOW).is_none());
    let recent = member("CN=recent,DC=x", &[DOMAIN_ADMINS], days_ago(1));
    assert!(check_inactive(&recent, &keys, &thresholds(), NOW).is_none());
    Ok(())
}


#[test]
fn a_disabled_unprivileged_or_computer_member_is_not_reported_inactive() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        entries: vec![group(DOMAIN_ADMINS, Some(ADMINS_SID))],
    };
    let keys = group_keys(&privileged_groups(&snapshot));
    let disabled = Entry {
        uac: UAC_NORMAL | UAC_DISABLED,
        ..member("CN=off,DC=x", &[DOMAIN_ADMINS], None)
    };
    assert!(check_inactive(&disabled, &keys, &thresholds(), NOW).is_none());
    let outsider = member("CN=out,DC=x", &["CN=Other,DC=x"], None);
    assert!(check_inactive(&outsider, &keys, &thresholds(), NOW).is_none());
    let computer = Entry {
        classes: vec!["user".to_owned(), "computer".to_owned()],
        ..member("CN=pc,DC=x", &[DOMAIN_ADMINS], None)
    };
    assert!(check_inactive(&computer, &keys, &thresholds(), NOW).is_none());
    Ok(())
}


#[test]
fn findings_are_ranked_by_severity_then_dn_and_the_score_follows() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        entries: vec![
            with_spn(user("CN=b-svc,DC=x", UAC_NORMAL)),
            with_spn(user("CN=a-svc,DC=x", UAC_NORMAL)),
            krbtgt(None),
            group(DOMAIN_ADMINS, Some(ADMINS_SID)),
            member("CN=admin,DC=x", &[DOMAIN_ADMINS], None),
        ],
    };
    let report = assess(&snapshot, &thresholds(), NOW);
    let order: Vec<(Severity, &str)> = report.findings.iter().map(|item| (item.severity, item.object.as_str())).collect();
    assert_eq!(
        order,
        vec![
            (Severity::Critical, "CN=krbtgt,CN=Users,DC=x"),
            (Severity::High, "CN=a-svc,DC=x"),
            (Severity::High, "CN=b-svc,DC=x"),
            (Severity::Medium, "CN=admin,DC=x"),
        ]
    );
    assert_eq!(report.score, SCORE_MAX - PENALTY_CRITICAL - PENALTY_HIGH - PENALTY_HIGH - PENALTY_MEDIUM);
    Ok(())
}


#[test]
fn one_object_with_two_findings_is_ordered_by_check() -> Result<(), Box<dyn Error>> {
    let both = Entry {
        uac: UAC_NORMAL | UAC_DONT_REQ_PREAUTH,
        ..with_spn(user("CN=x,DC=x", UAC_NORMAL))
    };
    let report = assess(&Snapshot { entries: vec![both] }, &thresholds(), NOW);
    let checks: Vec<Check> = report.findings.iter().map(|item| item.check).collect();
    assert_eq!(checks, vec![Check::Kerberoastable, Check::NoPreauth]);
    Ok(())
}


#[test]
fn the_score_never_goes_below_zero_and_covers_every_severity() -> Result<(), Box<dyn Error>> {
    let make = |severity| Finding {
        check: Check::NoPreauth,
        severity,
        object: "CN=a".to_owned(),
        reason: "r",
        fix: "f",
    };
    let many: Vec<Finding> = (0..MANY_FINDINGS).map(|_| make(Severity::Critical)).collect();
    assert_eq!(score_of(&many), 0);
    assert_eq!(score_of(&[make(Severity::Low)]), SCORE_MAX - PENALTY_LOW);
    assert_eq!(score_of(&[make(Severity::Medium)]), SCORE_MAX - PENALTY_MEDIUM);
    assert_eq!(score_of(&[]), SCORE_MAX);
    Ok(())
}


#[test]
fn the_report_prints_one_line_per_finding_and_a_score() -> Result<(), Box<dyn Error>> {
    let report = assess(
        &Snapshot {
            entries: vec![with_spn(user("CN=svc,DC=x", UAC_NORMAL))],
        },
        &thresholds(),
        NOW,
    );
    let lines = format_report(&report);
    assert_eq!(lines.len(), MAX_MEMBERS);
    assert_eq!(lines.first().map(String::as_str), report.findings.first().map(format_finding).as_deref());
    assert!(lines.first().is_some_and(|line| line.starts_with("High Kerberoastable CN=svc,DC=x | ")));
    assert_eq!(
        lines.last().map(String::as_str),
        Some(format!("score={} findings=1", SCORE_MAX - PENALTY_HIGH).as_str())
    );
    Ok(())
}
