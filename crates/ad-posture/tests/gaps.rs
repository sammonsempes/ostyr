use ad_posture::checks::{
    assess, bound_finding, check_dropped, check_group_size, check_incomplete_inactive, check_incomplete_kerberoast, check_kerberoastable,
    check_krbtgt_age, domain_sid, gap_detail, has_gap, has_over_limit, incomplete_severity, is_domain_privileged, unreadable_object,
};
use ad_posture::limits::Limits;
use ad_posture::model::{BoundHit, Check, Entry, Gap, Severity, Snapshot, Thresholds, Unreadable};
use ad_posture::report::report_lines;
use ad_posture::snapshot::read_snapshot;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;


const NOW: i64 = 1_700_000_000;


const THREE: usize = 3;


const UAC_NORMAL: u32 = 512;


const UAC_OFF: u32 = 514;


const LIMIT_DAYS: u32 = 180;


const MAX_MEMBERS: usize = 2;


const INACTIVE_DAYS: u32 = 90;


const TINY: u64 = 8;


const OBSERVED: u64 = 9;


const DOMAIN: &str = "S-1-5-21-1-2-3";


const DA_DN: &str = "CN=Domain Admins,CN=Users,DC=x";


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


fn with_gap(base: Entry, field: &'static str, over_limit: bool) -> Entry {
    Entry {
        gaps: vec![Gap {
            field,
            dropped: 1,
            over_limit,
        }],
        ..base
    }
}


fn with_sid(base: Entry, sid: &str) -> Entry {
    Entry {
        sid: Some(sid.to_owned()),
        ..base
    }
}


fn keys() -> BTreeSet<String> {
    BTreeSet::from([DA_DN.to_ascii_lowercase()])
}


fn domain_object(sid: &str) -> Entry {
    with_sid(entry("DC=x", &["top", "domainDNS"], 0), sid)
}


fn da_group() -> Entry {
    with_sid(entry(DA_DN, &["top", "group"], 0), "S-1-5-21-1-2-3-512")
}


fn krbtgt() -> Entry {
    with_sid(entry("CN=krbtgt,CN=Users,DC=x", &["top", "user"], UAC_OFF), "S-1-5-21-1-2-3-502")
}


fn snapshot_of(entries: Vec<Entry>) -> Snapshot {
    Snapshot {
        entries,
        ..Snapshot::default()
    }
}


#[test]
fn the_domain_sid_comes_from_the_domain_object_then_from_the_rid_512_group() -> Result<(), Box<dyn Error>> {
    assert_eq!(domain_sid(&snapshot_of(vec![domain_object(DOMAIN), da_group()])).as_deref(), Some(DOMAIN));
    assert_eq!(domain_sid(&snapshot_of(vec![da_group()])).as_deref(), Some(DOMAIN));
    assert_eq!(
        domain_sid(&snapshot_of(vec![domain_object("S-1-5-21-7-7-7"), da_group()])).as_deref(),
        Some("S-1-5-21-7-7-7")
    );
    assert_eq!(domain_sid(&snapshot_of(vec![entry("CN=a", &["top"], 0)])), None);
    let two_objects = snapshot_of(vec![domain_object(DOMAIN), domain_object("S-1-5-21-9-9-9")]);
    assert_eq!(domain_sid(&two_objects), None);
    let outside = snapshot_of(vec![domain_object("S-1-5-32-544")]);
    assert_eq!(domain_sid(&outside), None);
    let mixed = snapshot_of(vec![
        with_sid(entry("CN=builtin", &["group"], 0), "S-1-5-32-544"),
        entry("CN=nosid", &["group"], 0),
        with_sid(entry("CN=plain", &["group"], 0), "S-1-5-21-1-2-3-1100"),
        da_group(),
    ]);
    assert_eq!(domain_sid(&mixed).as_deref(), Some(DOMAIN));
    let krbtgt_only = snapshot_of(vec![krbtgt()]);
    assert_eq!(domain_sid(&krbtgt_only).as_deref(), Some(DOMAIN));
    let two_krbtgt = snapshot_of(vec![krbtgt(), with_sid(entry("CN=k2", &["user"], 0), "S-1-5-21-9-9-9-502")]);
    assert_eq!(domain_sid(&two_krbtgt), None);
    let user_512 = snapshot_of(vec![with_sid(entry("CN=u", &["user"], 0), "S-1-5-21-1-2-3-512")]);
    assert_eq!(domain_sid(&user_512), None);
    Ok(())
}


#[test]
fn privileged_sids_are_bound_to_the_domain() -> Result<(), Box<dyn Error>> {
    assert!(is_domain_privileged("S-1-5-32-544", None));
    assert!(is_domain_privileged("S-1-5-21-1-2-3-519", Some(DOMAIN)));
    assert!(!is_domain_privileged("S-1-5-21-9-9-9-512", Some(DOMAIN)));
    assert!(!is_domain_privileged("S-1-5-21-1-2-3-512", None));
    assert!(!is_domain_privileged("S-1-5-21-1-2-3-5120", Some(DOMAIN)));
    Ok(())
}


#[test]
fn a_gap_is_found_by_field_and_described_by_numbers_only() -> Result<(), Box<dyn Error>> {
    let dropped = with_gap(entry("CN=a", &["user"], 0), "memberOf", false);
    assert!(has_gap(&dropped, &["memberOf"]) && !has_gap(&dropped, &["objectClass"]));
    assert_eq!(gap_detail(&dropped), "memberOf dropped 1");
    let over = with_gap(entry("CN=a", &["user"], 0), "servicePrincipalName", true);
    assert_eq!(gap_detail(&over), "servicePrincipalName dropped 1 (list over its count, none kept)");
    assert_eq!(gap_detail(&entry("CN=a", &[], 0)), "");
    let finding = check_dropped(&dropped).ok_or("no finding")?;
    assert_eq!((finding.check, finding.severity), (Check::DroppedValues, Severity::Low));
    assert_eq!(finding.detail, "memberOf dropped 1");
    assert!(check_dropped(&entry("CN=a", &[], 0)).is_none());
    Ok(())
}


#[test]
fn a_krbtgt_with_a_poisoned_member_of_keeps_its_critical_finding() -> Result<(), Box<dyn Error>> {
    let poisoned = with_gap(krbtgt(), "memberOf", false);
    let report = assess(&snapshot_of(vec![da_group(), poisoned]), &thresholds(), NOW);
    let found: Vec<(Severity, Check, &str)> = report
        .findings
        .iter()
        .map(|item| (item.severity, item.check, item.object.as_str()))
        .collect();
    assert!(found.contains(&(Severity::Critical, Check::KrbtgtPasswordAge, "CN=krbtgt,CN=Users,DC=x")));
    assert!(found.contains(&(Severity::Low, Check::DroppedValues, "CN=krbtgt,CN=Users,DC=x")));
    assert!(!found.iter().any(|item| item.1 == Check::IncompleteCheck));
    assert!(!found.iter().any(|item| item.1 == Check::UnreadableObject));
    let over = with_gap(krbtgt(), "memberOf", true);
    let report_over = assess(&snapshot_of(vec![da_group(), over]), &thresholds(), NOW);
    assert!(report_over
        .findings
        .iter()
        .any(|item| (item.severity, item.check, item.object.as_str()) == (Severity::Critical, Check::IncompleteCheck, DA_DN)));
    Ok(())
}


#[test]
fn group_size_is_never_silently_a_lower_bound() -> Result<(), Box<dyn Error>> {
    let group = da_group();
    let counts = BTreeMap::from([(DA_DN.to_ascii_lowercase(), THREE)]);
    let big = check_group_size(&group, &counts, &thresholds(), THREE).ok_or("no finding")?;
    assert_eq!(big.check, Check::PrivilegedGroupSize);
    let none = BTreeMap::new();
    assert!(check_group_size(&group, &none, &thresholds(), 0).is_none());
    let unknown = check_group_size(&group, &none, &thresholds(), THREE).ok_or("no finding")?;
    assert_eq!((unknown.check, unknown.severity), (Check::IncompleteCheck, Severity::Critical));
    assert_eq!(unknown.object, DA_DN);
    assert_eq!(unknown.detail, "memberOf of 3 entries is over its count");
    Ok(())
}


#[test]
fn an_incomplete_kerberoast_check_names_the_entry() -> Result<(), Box<dyn Error>> {
    let class_refused = with_gap(entry("CN=svc,DC=x", &[], UAC_NORMAL), "objectClass", false);
    let finding = check_incomplete_kerberoast(&class_refused, Some(DOMAIN), &keys()).ok_or("no finding")?;
    assert_eq!(
        (finding.check, finding.severity, finding.object.as_str()),
        (Check::IncompleteCheck, Severity::High, "CN=svc,DC=x")
    );
    let class_gap = with_gap(entry("CN=svc,DC=x", &[], UAC_NORMAL), "objectClass", true);
    assert!(check_incomplete_kerberoast(&class_gap, Some(DOMAIN), &keys()).is_some());
    let computer = with_gap(entry("CN=pc,DC=x", &["user", "computer"], UAC_NORMAL), "servicePrincipalName", true);
    assert!(check_incomplete_kerberoast(&computer, Some(DOMAIN), &keys()).is_none());
    let disabled = with_gap(entry("CN=off,DC=x", &["user"], UAC_OFF), "servicePrincipalName", true);
    assert!(check_incomplete_kerberoast(&disabled, Some(DOMAIN), &keys()).is_none());
    let no_gap = entry("CN=ok,DC=x", &["user"], UAC_NORMAL);
    assert!(check_incomplete_kerberoast(&no_gap, Some(DOMAIN), &keys()).is_none());
    let refused_only = with_gap(entry("CN=svc,DC=x", &["user"], UAC_NORMAL), "servicePrincipalName", false);
    assert!(check_incomplete_kerberoast(&refused_only, Some(DOMAIN), &keys()).is_none());
    assert!(check_kerberoastable(&refused_only).is_some());
    let over_count = with_gap(entry("CN=svc,DC=x", &["user"], UAC_NORMAL), "servicePrincipalName", true);
    assert!(check_incomplete_kerberoast(&over_count, Some(DOMAIN), &keys()).is_none());
    assert!(check_kerberoastable(&over_count).is_some());
    let decided = Entry {
        spns: vec!["http/a".to_owned()],
        ..with_gap(entry("CN=svc,DC=x", &["user"], UAC_NORMAL), "memberOf", false)
    };
    assert!(check_incomplete_kerberoast(&decided, Some(DOMAIN), &keys()).is_none());
    Ok(())
}


#[test]
fn an_incomplete_inactive_check_is_reported_only_when_it_could_matter() -> Result<(), Box<dyn Error>> {
    let stale = with_gap(entry("CN=a,DC=x", &["user"], UAC_NORMAL), "memberOf", true);
    let finding = check_incomplete_inactive(&stale, Some(DOMAIN), &keys(), &thresholds(), NOW).ok_or("no finding")?;
    assert_eq!((finding.check, finding.severity), (Check::IncompleteCheck, Severity::High));
    let refused_only = with_gap(entry("CN=a,DC=x", &["user"], UAC_NORMAL), "memberOf", false);
    assert!(check_incomplete_inactive(&refused_only, Some(DOMAIN), &keys(), &thresholds(), NOW).is_none());
    let active = Entry {
        last_logon: Some(NOW),
        ..stale.clone()
    };
    assert!(check_incomplete_inactive(&active, Some(DOMAIN), &keys(), &thresholds(), NOW).is_none());
    let known_member = Entry {
        member_of: vec![DA_DN.to_owned()],
        ..stale.clone()
    };
    assert!(check_incomplete_inactive(&known_member, Some(DOMAIN), &keys(), &thresholds(), NOW).is_none());
    let computer = with_gap(entry("CN=pc", &["user", "computer"], UAC_NORMAL), "memberOf", true);
    assert!(check_incomplete_inactive(&computer, Some(DOMAIN), &keys(), &thresholds(), NOW).is_none());
    let disabled = with_gap(entry("CN=off", &["user"], UAC_OFF), "memberOf", true);
    assert!(check_incomplete_inactive(&disabled, Some(DOMAIN), &keys(), &thresholds(), NOW).is_none());
    let no_gap = entry("CN=ok", &["user"], UAC_NORMAL);
    assert!(check_incomplete_inactive(&no_gap, Some(DOMAIN), &keys(), &thresholds(), NOW).is_none());
    let class_gap_member = Entry {
        member_of: vec![DA_DN.to_owned()],
        ..with_gap(entry("CN=m", &[], UAC_NORMAL), "objectClass", true)
    };
    let critical = check_incomplete_inactive(&class_gap_member, Some(DOMAIN), &keys(), &thresholds(), NOW).ok_or("no finding")?;
    assert_eq!(critical.severity, Severity::Critical);
    Ok(())
}


#[test]
fn the_severity_of_an_incomplete_check_follows_the_subject() -> Result<(), Box<dyn Error>> {
    assert_eq!(incomplete_severity(&krbtgt(), Some(DOMAIN), &keys()), Severity::Critical);
    assert_eq!(incomplete_severity(&da_group(), Some(DOMAIN), &keys()), Severity::Critical);
    let member = Entry {
        member_of: vec![DA_DN.to_owned()],
        ..entry("CN=m", &["user"], UAC_NORMAL)
    };
    assert_eq!(incomplete_severity(&member, Some(DOMAIN), &keys()), Severity::Critical);
    assert_eq!(
        incomplete_severity(&entry("CN=u", &["user"], UAC_NORMAL), Some(DOMAIN), &keys()),
        Severity::High
    );
    let plain_group = with_sid(entry("CN=g", &["group"], 0), "S-1-5-21-1-2-3-1100");
    assert_eq!(incomplete_severity(&plain_group, Some(DOMAIN), &keys()), Severity::High);
    Ok(())
}


#[test]
fn a_foreign_principal_with_the_krbtgt_rid_forges_nothing() -> Result<(), Box<dyn Error>> {
    let fsp = with_sid(
        entry(
            "CN=S-1-5-21-9-9-9-502,CN=ForeignSecurityPrincipals,DC=x",
            &["foreignSecurityPrincipal"],
            0,
        ),
        "S-1-5-21-9-9-9-502",
    );
    let report = assess(&snapshot_of(vec![da_group(), fsp]), &thresholds(), NOW);
    assert!(report.findings.is_empty());
    Ok(())
}


#[test]
fn a_privileged_looking_sid_without_a_domain_is_a_critical_finding() -> Result<(), Box<dyn Error>> {
    let two_krbtgt = snapshot_of(vec![krbtgt(), with_sid(entry("CN=k2", &["user"], 0), "S-1-5-21-9-9-9-502")]);
    let report = assess(&two_krbtgt, &thresholds(), NOW);
    let finding = report.findings.first().ok_or("no finding")?;
    assert_eq!((finding.check, finding.severity), (Check::AssessmentIncomplete, Severity::Critical));
    assert_eq!(finding.detail, "domain SID missing or ambiguous");
    let group_only = Entry {
        sid: Some("S-1-5-21-1-2-3-512".to_owned()),
        classes: vec!["group".to_owned(), "x".to_owned()],
        ..entry("CN=g", &[], 0)
    };
    let two_domains = snapshot_of(vec![group_only.clone(), with_sid(entry("CN=h", &["group"], 0), "S-1-5-21-4-4-4-512")]);
    assert_eq!(assess(&two_domains, &thresholds(), NOW).findings.len(), 1);
    assert!(assess(&snapshot_of(vec![entry("CN=a", &["user"], UAC_NORMAL)]), &thresholds(), NOW)
        .findings
        .is_empty());
    let unrelated = snapshot_of(vec![
        with_sid(entry("CN=u", &["user"], UAC_NORMAL), "S-1-5-21-1-2-3-1105"),
        with_sid(entry("CN=v", &["user"], UAC_NORMAL), "S-1-5-5-502"),
        with_sid(entry("CN=b", &["group"], 0), "S-1-5-32-544"),
        with_sid(entry("CN=g", &["group"], 0), "S-1-5-21-1-2-3-1100"),
    ]);
    assert!(assess(&unrelated, &thresholds(), NOW)
        .findings
        .iter()
        .all(|item| item.check != Check::AssessmentIncomplete));
    assert!(assess(&snapshot_of(vec![da_group(), krbtgt()]), &thresholds(), NOW)
        .findings
        .iter()
        .all(|item| item.check != Check::AssessmentIncomplete));
    assert!(check_krbtgt_age(&krbtgt(), None, &thresholds(), NOW).is_none());
    Ok(())
}


#[test]
fn a_bound_hit_is_a_critical_finding_and_the_run_still_reports() -> Result<(), Box<dyn Error>> {
    let hit = BoundHit {
        bound: "bytes",
        observed: OBSERVED,
        limit: TINY,
    };
    let finding = bound_finding(&hit);
    assert_eq!((finding.check, finding.severity), (Check::AssessmentIncomplete, Severity::Critical));
    assert_eq!(finding.detail, "bound bytes observed 9 limit 8");
    let tiny = Limits {
        max_bytes: TINY,
        ..Limits::default()
    };
    let snapshot = read_snapshot("[{\"distinguishedName\":\"CN=a\"}]".as_bytes(), &tiny)?;
    let report = assess(&snapshot, &thresholds(), NOW);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.score, None);
    let lines: Vec<String> = report_lines(&report).collect();
    assert_eq!(lines.len(), MAX_MEMBERS);
    let last: serde_json::Value = serde_json::from_str(lines.last().ok_or("no line")?)?;
    assert_eq!(last.get("score"), Some(&serde_json::Value::Null));
    assert_eq!(last.get("scored"), Some(&serde_json::json!(false)));
    Ok(())
}


#[test]
fn an_unreadable_entry_names_its_account_and_sid_when_readable() -> Result<(), Box<dyn Error>> {
    let item = Unreadable {
        index: 1,
        field: "pwdLastSet",
        reason: "FILETIME out of range",
        dn_digest: "0123456789abcdef".to_owned(),
        group_risk: false,
        account: Some("krbtgt".to_owned()),
        sid: Some("S-1-5-21-1-2-3-502".to_owned()),
    };
    assert_eq!(
        unreadable_object(&item),
        "entry 1 field pwdLastSet reason FILETIME out of range dn-sha256 0123456789abcdef account krbtgt sid S-1-5-21-1-2-3-502"
    );
    Ok(())
}


#[test]
fn a_bidi_group_that_lists_krbtgt_as_a_member_blanks_nothing() -> Result<(), Box<dyn Error>> {
    let text = "[{\"distinguishedName\":\"CN=Domain Admins,CN=Users,DC=x\",\"objectClass\":[\"group\"],\"objectSid\":\"S-1-5-21-1-2-3-512\"},\
        {\"distinguishedName\":\"CN=krbtgt,CN=Users,DC=x\",\"objectClass\":[\"user\"],\"userAccountControl\":514,\"objectSid\":\"S-1-5-21-1-2-3-502\",\
         \"sAMAccountName\":\"krbtgt\",\"memberOf\":[\"CN=grp\\u202eevil,OU=H,DC=x\"]},\
        {\"distinguishedName\":\"CN=svc,DC=x\",\"objectClass\":[\"user\"],\"userAccountControl\":512,\"servicePrincipalName\":[\"http/a\"],\
         \"memberOf\":[\"CN=grp\\u202eevil,OU=H,DC=x\"]},\
        {\"distinguishedName\":\"CN=grp\\u202eevil,OU=H,DC=x\",\"objectClass\":[\"group\"]}]";
    let snapshot = read_snapshot(text.as_bytes(), &Limits::default())?;
    assert_eq!(snapshot.unreadable.len(), 1);
    let report = assess(&snapshot, &thresholds(), NOW);
    let found: Vec<(Check, &str)> = report.findings.iter().map(|item| (item.check, item.object.as_str())).collect();
    assert!(found.contains(&(Check::KrbtgtPasswordAge, "CN=krbtgt,CN=Users,DC=x")));
    assert!(found.contains(&(Check::Kerberoastable, "CN=svc,DC=x")));
    assert!(found.contains(&(Check::DroppedValues, "CN=krbtgt,CN=Users,DC=x")));
    assert!(!found.iter().any(|item| item.0 == Check::IncompleteCheck));
    assert!(report.score.is_some());
    Ok(())
}


#[test]
fn a_thousand_and_one_groups_on_krbtgt_do_not_hide_it() -> Result<(), Box<dyn Error>> {
    let groups = (0..=Limits::default().max_values)
        .map(|i| format!("\"CN=g{i},DC=x\""))
        .collect::<Vec<_>>()
        .join(",");
    let text = format!(
        "[{{\"distinguishedName\":\"CN=Domain Admins,CN=Users,DC=x\",\"objectClass\":[\"group\"],\"objectSid\":\"S-1-5-21-1-2-3-512\"}},\
         {{\"distinguishedName\":\"CN=krbtgt,CN=Users,DC=x\",\"objectClass\":[\"user\"],\"objectSid\":\"S-1-5-21-1-2-3-502\",\"memberOf\":[{groups}]}}]"
    );
    let snapshot = read_snapshot(text.as_bytes(), &Limits::default())?;
    let report = assess(&snapshot, &thresholds(), NOW);
    let checks: Vec<Check> = report.findings.iter().map(|item| item.check).collect();
    assert!(checks.contains(&Check::KrbtgtPasswordAge) && checks.contains(&Check::IncompleteCheck) && checks.contains(&Check::DroppedValues));
    Ok(())
}


#[test]
fn an_undeterminable_domain_has_no_score() -> Result<(), Box<dyn Error>> {
    let other = with_sid(entry("CN=krbtgt,CN=Users,DC=y", &["top", "user"], UAC_OFF), "S-1-5-21-9-9-9-502");
    let report = assess(&snapshot_of(vec![krbtgt(), other]), &thresholds(), NOW);
    assert!(report.findings.iter().any(|item| item.check == Check::AssessmentIncomplete));
    assert_eq!(report.score, None);
    Ok(())
}


#[test]
fn padding_a_snapshot_past_a_bound_never_scores_it_better() -> Result<(), Box<dyn Error>> {
    let fixtures = [
        vec![],
        vec![da_group(), krbtgt()],
        vec![domain_object(DOMAIN), da_group(), krbtgt(), entry("CN=svc,DC=x", &["user"], UAC_NORMAL)],
    ];
    let padded_limits = Limits {
        max_bytes: TINY,
        ..Limits::default()
    };
    fixtures.into_iter().try_for_each(|entries| -> Result<(), Box<dyn Error>> {
        let plain = assess(&snapshot_of(entries.clone()), &thresholds(), NOW);
        let padded_snapshot = read_snapshot("[{\"distinguishedName\":\"CN=padding\"}]".as_bytes(), &padded_limits)?;
        let padded = Snapshot {
            entries,
            bounds: padded_snapshot.bounds,
            ..Snapshot::default()
        };
        let padded_report = assess(&padded, &thresholds(), NOW);
        assert_eq!(padded_report.score, None);
        assert!(padded_report.score.unwrap_or(0) <= plain.score.unwrap_or(0));
        Ok(())
    })
}


#[test]
fn only_a_list_over_its_count_is_over_limit() -> Result<(), Box<dyn Error>> {
    let refused = with_gap(entry("CN=a", &["user"], 0), "memberOf", false);
    assert!(!has_over_limit(&refused, &["memberOf"]));
    let over = with_gap(entry("CN=a", &["user"], 0), "memberOf", true);
    assert!(has_over_limit(&over, &["memberOf"]) && !has_over_limit(&over, &["objectClass"]));
    Ok(())
}


#[test]
fn a_refused_spn_never_scores_above_a_plain_spn() -> Result<(), Box<dyn Error>> {
    let plain = Entry {
        spns: vec!["http/app".to_owned()],
        ..entry("CN=svc,DC=x", &["user"], UAC_NORMAL)
    };
    let refused = with_gap(entry("CN=svc,DC=x", &["user"], UAC_NORMAL), "servicePrincipalName", false);
    let over = with_gap(entry("CN=svc,DC=x", &["user"], UAC_NORMAL), "servicePrincipalName", true);
    let score_of_entry = |item: Entry| -> Result<u32, Box<dyn Error>> {
        let snapshot = Snapshot {
            entries: vec![item],
            ..Snapshot::default()
        };
        assess(&snapshot, &thresholds(), NOW).score.ok_or_else(|| "no score".into())
    };
    let base = score_of_entry(plain)?;
    assert!(score_of_entry(refused)? <= base);
    assert!(score_of_entry(over)? <= base);
    Ok(())
}


#[test]
fn a_finding_names_only_the_gaps_of_the_fields_its_check_reads() -> Result<(), Box<dyn Error>> {
    let plain = Entry {
        spns: vec!["http/x".to_owned()],
        ..with_gap(entry("CN=svc", &["user"], UAC_NORMAL), "memberOf", false)
    };
    let roast = check_kerberoastable(&plain).ok_or("no finding")?;
    assert!(!roast.detail.contains("memberOf"));
    let dropped = check_dropped(&plain).ok_or("no finding")?;
    assert!(dropped.detail.contains("memberOf"));
    Ok(())
}
