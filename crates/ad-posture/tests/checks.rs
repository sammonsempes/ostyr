use ad_posture::checks::{
    assess, check_group_size, check_inactive, check_kerberoastable, check_krbtgt_age, check_no_preauth, check_unconstrained_delegation, group_keys,
    is_privileged_sid, member_counts, privileged_groups, score_of, FIX_KERBEROASTABLE, PENALTY_CRITICAL, PENALTY_HIGH, PENALTY_LOW, PENALTY_MEDIUM,
    REASON_KERBEROASTABLE, SCORE_MAX, SECONDS_PER_DAY, UAC_DISABLED, UAC_DONT_REQ_PREAUTH, UAC_SERVER_TRUST, UAC_TRUSTED_FOR_DELEGATION,
};
use ad_posture::model::{Check, Entry, Finding, Severity, Snapshot, Thresholds, Unreadable};
use ad_posture::report::{format_finding, report_lines};
use std::error::Error;


const NOW: i64 = 1_700_000_000;


const DAYS: i64 = SECONDS_PER_DAY;


const LIMIT_DAYS: u32 = 180;


const INACTIVE_DAYS: u32 = 90;


const MAX_MEMBERS: usize = 2;


const UAC_NORMAL: u32 = 512;


const UAC_KRBTGT: u32 = 514;


const THREE_INDEX: usize = 3;


const MANY_FINDINGS: usize = 10;


const ADMINS_SID: &str = "S-1-5-21-1-2-3-512";


const KRBTGT_SID: &str = "S-1-5-21-1-2-3-502";


const DOMAIN: Option<&str> = Some("S-1-5-21-1-2-3");


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
        gaps: Vec::new(),
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
        sid: Some(KRBTGT_SID.to_owned()),
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
    let old = found(check_krbtgt_age(&krbtgt(days_ago(i64::from(LIMIT_DAYS) + 1)), DOMAIN, &thresholds(), NOW))?;
    assert_eq!(old.check, Check::KrbtgtPasswordAge);
    assert_eq!(old.severity, Severity::Critical);
    assert!(check_krbtgt_age(&krbtgt(None), DOMAIN, &thresholds(), NOW).is_some());
    Ok(())
}


#[test]
fn a_recent_krbtgt_password_and_other_accounts_are_not_reported() -> Result<(), Box<dyn Error>> {
    assert!(check_krbtgt_age(&krbtgt(days_ago(i64::from(LIMIT_DAYS))), DOMAIN, &thresholds(), NOW).is_none());
    assert!(check_krbtgt_age(&krbtgt(Some(NOW + DAYS)), DOMAIN, &thresholds(), NOW).is_none());
    Ok(())
}


#[test]
fn krbtgt_is_identified_by_its_rid_never_by_its_name() -> Result<(), Box<dyn Error>> {
    let forged = Entry {
        sid: Some("S-1-5-21-1-2-3-1105".to_owned()),
        ..krbtgt(None)
    };
    assert!(check_krbtgt_age(&forged, DOMAIN, &thresholds(), NOW).is_none());
    let nameless = Entry {
        account: None,
        ..krbtgt(None)
    };
    assert!(check_krbtgt_age(&nameless, DOMAIN, &thresholds(), NOW).is_some());
    let no_sid = Entry { sid: None, ..krbtgt(None) };
    assert!(check_krbtgt_age(&no_sid, DOMAIN, &thresholds(), NOW).is_none());
    let wrong_domain = Entry {
        sid: Some("S-1-5-5-502".to_owned()),
        ..krbtgt(None)
    };
    assert!(check_krbtgt_age(&wrong_domain, DOMAIN, &thresholds(), NOW).is_none());
    let foreign_domain = Entry {
        sid: Some("S-1-5-21-9-9-9-502".to_owned()),
        ..krbtgt(None)
    };
    assert!(check_krbtgt_age(&foreign_domain, DOMAIN, &thresholds(), NOW).is_none());
    assert!(check_krbtgt_age(&krbtgt(None), None, &thresholds(), NOW).is_none());
    let principal = Entry {
        classes: vec!["foreignSecurityPrincipal".to_owned()],
        sid: Some("S-1-5-21-1-2-3-502".to_owned()),
        ..krbtgt(None)
    };
    assert!(check_krbtgt_age(&principal, DOMAIN, &thresholds(), NOW).is_none());
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
        ..Snapshot::default()
    };
    let groups = privileged_groups(&snapshot, DOMAIN);
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
        ..Snapshot::default()
    };
    let keys = group_keys(&privileged_groups(&snapshot, DOMAIN));
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
    let at_limit = Snapshot {
        entries: entries.clone(),
        ..Snapshot::default()
    };
    let report = assess(&at_limit, &thresholds(), NOW);
    assert!(report.findings.is_empty());
    assert_eq!(report.score, SCORE_MAX);
    entries.push(member("CN=c,DC=x", &[DOMAIN_ADMINS], days_ago(1)));
    let above = Snapshot {
        entries,
        ..Snapshot::default()
    };
    let report_above = assess(&above, &thresholds(), NOW);
    let finding = report_above.findings.first().ok_or("no finding")?;
    assert_eq!(finding.check, Check::PrivilegedGroupSize);
    assert_eq!(finding.object, DOMAIN_ADMINS);
    assert_eq!(report_above.findings.len(), 1);
    let keys = group_keys(&privileged_groups(&above, DOMAIN));
    let empty = Snapshot {
        entries: vec![group(DOMAIN_ADMINS, Some(ADMINS_SID))],
        ..Snapshot::default()
    };
    let empty_group = empty.entries.first().ok_or("no group")?;
    assert!(check_group_size(empty_group, &member_counts(&empty, &keys), &thresholds(), 0).is_none());
    Ok(())
}


#[test]
fn an_inactive_privileged_user_is_reported() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        entries: vec![group(DOMAIN_ADMINS, Some(ADMINS_SID))],
        ..Snapshot::default()
    };
    let keys = group_keys(&privileged_groups(&snapshot, DOMAIN));
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
        ..Snapshot::default()
    };
    let keys = group_keys(&privileged_groups(&snapshot, DOMAIN));
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
        ..Snapshot::default()
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
    let report = assess(
        &Snapshot {
            entries: vec![both],
            ..Snapshot::default()
        },
        &thresholds(),
        NOW,
    );
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
        detail: String::new(),
    };
    let many: Vec<Finding> = (0..MANY_FINDINGS).map(|_| make(Severity::Critical)).collect();
    assert_eq!(score_of(&many), 0);
    assert_eq!(score_of(&[make(Severity::Low)]), SCORE_MAX - PENALTY_LOW);
    assert_eq!(score_of(&[make(Severity::Medium)]), SCORE_MAX - PENALTY_MEDIUM);
    assert_eq!(score_of(&[]), SCORE_MAX);
    Ok(())
}


fn aside(index: usize, group_risk: bool) -> Unreadable {
    Unreadable {
        index,
        field: "distinguishedName",
        reason: "unsafe character",
        dn_digest: "0123456789abcdef".to_owned(),
        group_risk,
        account: None,
        sid: None,
    }
}


#[test]
fn an_entry_set_aside_is_a_high_finding_without_input_text() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        unreadable: vec![aside(THREE_INDEX, false)],
        ..Snapshot::default()
    };
    let report = assess(&snapshot, &thresholds(), NOW);
    let item = report.findings.first().ok_or("no finding")?;
    assert_eq!((item.check, item.severity), (Check::UnreadableObject, Severity::High));
    assert_eq!(
        item.object,
        "entry 3 field distinguishedName reason unsafe character dn-sha256 0123456789abcdef"
    );
    assert_eq!(report.findings.len(), 1);
    Ok(())
}


#[test]
fn an_unreadable_privileged_group_is_critical() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        unreadable: vec![aside(0, true)],
        ..Snapshot::default()
    };
    let report = assess(&snapshot, &thresholds(), NOW);
    let order: Vec<(Severity, Check)> = report.findings.iter().map(|item| (item.severity, item.check)).collect();
    assert_eq!(
        order,
        vec![
            (Severity::Critical, Check::PrivilegedGroupUnreadable),
            (Severity::High, Check::UnreadableObject)
        ]
    );
    Ok(())
}


#[test]
fn a_set_aside_entry_does_not_hide_the_other_findings() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        entries: vec![with_spn(user("CN=svc,DC=x", UAC_NORMAL))],
        unreadable: vec![aside(1, false)],
        ..Snapshot::default()
    };
    let checks: Vec<Check> = assess(&snapshot, &thresholds(), NOW).findings.iter().map(|item| item.check).collect();
    assert_eq!(checks, vec![Check::Kerberoastable, Check::UnreadableObject]);
    Ok(())
}


#[test]
fn a_dn_that_only_folds_to_a_group_name_is_not_a_member() -> Result<(), Box<dyn Error>> {
    let snapshot = Snapshot {
        entries: vec![group("CN=KPC,DC=x", Some(ADMINS_SID))],
        ..Snapshot::default()
    };
    let keys = group_keys(&privileged_groups(&snapshot, DOMAIN));
    let twin = member("CN=a,DC=x", &["CN=\u{212A}PC,DC=x"], None);
    assert!(check_inactive(&twin, &keys, &thresholds(), NOW).is_none());
    let real = member("CN=b,DC=x", &["cn=kpc,dc=X"], None);
    assert!(check_inactive(&real, &keys, &thresholds(), NOW).is_some());
    Ok(())
}


#[test]
fn the_report_is_one_json_object_per_line_that_no_dn_can_forge() -> Result<(), Box<dyn Error>> {
    let dn = "CN=a\" | harmless | fix: none\",DC=x";
    let report = assess(
        &Snapshot {
            entries: vec![with_spn(user(dn, UAC_NORMAL))],
            ..Snapshot::default()
        },
        &thresholds(),
        NOW,
    );
    let lines: Vec<String> = report_lines(&report).collect();
    assert_eq!(lines.len(), MAX_MEMBERS);
    let first: serde_json::Value = serde_json::from_str(lines.first().ok_or("no line")?)?;
    assert_eq!(first.get("object"), Some(&serde_json::json!(dn)));
    assert_eq!(first.get("severity"), Some(&serde_json::json!("High")));
    assert_eq!(first.get("check"), Some(&serde_json::json!("Kerberoastable")));
    assert_eq!(first.get("fix"), Some(&serde_json::json!(FIX_KERBEROASTABLE)));
    assert_eq!(first.get("reason"), Some(&serde_json::json!(REASON_KERBEROASTABLE)));
    assert_eq!(lines.first().map(String::as_str), report.findings.first().map(format_finding).as_deref());
    let last: serde_json::Value = serde_json::from_str(lines.last().ok_or("no line")?)?;
    assert_eq!(last.get("score"), Some(&serde_json::json!(SCORE_MAX - PENALTY_HIGH)));
    assert_eq!(last.get("findings"), Some(&serde_json::json!(1)));
    Ok(())
}
