use crate::model::{Check, Entry, Finding, Report, Severity, Snapshot, Thresholds, Unreadable};
use std::collections::{BTreeMap, BTreeSet};


/// `ACCOUNTDISABLE`.
pub const UAC_DISABLED: u32 = 0x2;


/// `SERVER_TRUST_ACCOUNT`: a domain controller's computer account.
pub const UAC_SERVER_TRUST: u32 = 0x2000;


/// `TRUSTED_FOR_DELEGATION`: unconstrained Kerberos delegation.
pub const UAC_TRUSTED_FOR_DELEGATION: u32 = 0x8_0000;


/// `DONT_REQ_PREAUTH`.
pub const UAC_DONT_REQ_PREAUTH: u32 = 0x40_0000;


pub const SECONDS_PER_DAY: i64 = 86_400;


/// The krbtgt account is identified by its well-known RID, never by its name.
pub const KRBTGT_RID_SUFFIX: &str = "-502";


pub const CLASS_USER: &str = "user";


pub const CLASS_COMPUTER: &str = "computer";


pub const CLASS_GROUP: &str = "group";


/// The built-in Administrators group.
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";


pub const DOMAIN_SID_PREFIX: &str = "S-1-5-21-";


/// Domain Admins, Schema Admins, Enterprise Admins.
pub const PRIVILEGED_RID_SUFFIXES: [&str; 3] = ["-512", "-518", "-519"];


pub const PENALTY_CRITICAL: u32 = 40;


pub const PENALTY_HIGH: u32 = 15;


pub const PENALTY_MEDIUM: u32 = 5;


pub const PENALTY_LOW: u32 = 1;


/// Findings one set-aside entry can give: the entry itself and a possible privileged group.
pub const UNREADABLE_FINDINGS: usize = 2;


pub const SCORE_MAX: u32 = 100;


pub const REASON_KERBEROASTABLE: &str = "an enabled user account has a service principal name, so any user can request and crack its ticket";


pub const FIX_KERBEROASTABLE: &str = "remove the SPN or use a group managed service account with a long random password";


pub const REASON_NO_PREAUTH: &str = "Kerberos pre-authentication is not required, so its password hash can be requested without credentials";


pub const FIX_NO_PREAUTH: &str = "clear DONT_REQ_PREAUTH on the account";


pub const REASON_DELEGATION: &str = "unconstrained delegation on a non-domain-controller: it can impersonate any user that authenticates to it";


pub const FIX_DELEGATION: &str = "switch to constrained or resource-based delegation, or clear TRUSTED_FOR_DELEGATION";


pub const REASON_KRBTGT: &str = "the krbtgt password is older than the threshold or has no recorded change";


pub const FIX_KRBTGT: &str = "reset the krbtgt password twice, with the replication delay between the resets";


pub const REASON_GROUP_SIZE: &str = "a privileged group has more direct members than the threshold";


pub const FIX_GROUP_SIZE: &str = "remove members that do not need the privilege";


pub const REASON_INACTIVE: &str = "an enabled privileged account has no recent logon";


pub const FIX_INACTIVE: &str = "disable the account or remove it from the privileged group";


pub const REASON_UNREADABLE: &str = "this directory entry could not be read and was left out of every check";


pub const FIX_UNREADABLE: &str = "inspect the object on the domain controller: it may be hostile or the export may be broken";


pub const REASON_GROUP_UNREADABLE: &str = "a privileged group could not be read, so its members cannot be assessed";


pub const FIX_GROUP_UNREADABLE: &str = "fix or remove the unreadable group entry, then export again";


pub fn has_class(entry: &Entry, class: &str) -> bool {
    entry.classes.iter().any(|found| found.eq_ignore_ascii_case(class))
}


pub fn is_enabled(entry: &Entry) -> bool {
    entry.uac & UAC_DISABLED == 0
}


pub fn is_plain_user(entry: &Entry) -> bool {
    has_class(entry, CLASS_USER) && !has_class(entry, CLASS_COMPUTER) && is_enabled(entry)
}


pub fn finding_of(check: Check, severity: Severity, object: String, reason: &'static str, fix: &'static str) -> Finding {
    Finding {
        severity,
        check,
        object,
        reason,
        fix,
    }
}


pub fn finding(check: Check, severity: Severity, entry: &Entry, reason: &'static str, fix: &'static str) -> Finding {
    finding_of(check, severity, entry.dn.clone(), reason, fix)
}


/// Names an unreadable entry by position, field, fixed reason and DN digest: never by input text.
pub fn unreadable_object(item: &Unreadable) -> String {
    format!(
        "entry {} field {} reason {} dn-sha256 {}",
        item.index, item.field, item.reason, item.dn_digest
    )
}


/// One High finding per entry set aside, plus a Critical one when it may be a privileged group.
pub fn unreadable_findings(item: &Unreadable) -> [Option<Finding>; UNREADABLE_FINDINGS] {
    [
        Some(finding_of(
            Check::UnreadableObject,
            Severity::High,
            unreadable_object(item),
            REASON_UNREADABLE,
            FIX_UNREADABLE,
        )),
        item.group_risk.then(|| {
            finding_of(
                Check::PrivilegedGroupUnreadable,
                Severity::Critical,
                unreadable_object(item),
                REASON_GROUP_UNREADABLE,
                FIX_GROUP_UNREADABLE,
            )
        }),
    ]
}


/// An enabled user (a computer is not one) with a service principal name.
pub fn check_kerberoastable(entry: &Entry) -> Option<Finding> {
    (is_plain_user(entry) && !entry.spns.is_empty())
        .then(|| finding(Check::Kerberoastable, Severity::High, entry, REASON_KERBEROASTABLE, FIX_KERBEROASTABLE))
}


/// An enabled account that does not require pre-authentication; a disabled one is not reported.
pub fn check_no_preauth(entry: &Entry) -> Option<Finding> {
    (is_enabled(entry) && entry.uac & UAC_DONT_REQ_PREAUTH != 0)
        .then(|| finding(Check::NoPreauth, Severity::High, entry, REASON_NO_PREAUTH, FIX_NO_PREAUTH))
}


/// An enabled account trusted for delegation that is not a domain controller.
pub fn check_unconstrained_delegation(entry: &Entry) -> Option<Finding> {
    (is_enabled(entry) && entry.uac & UAC_TRUSTED_FOR_DELEGATION != 0 && entry.uac & UAC_SERVER_TRUST == 0)
        .then(|| finding(Check::UnconstrainedDelegation, Severity::High, entry, REASON_DELEGATION, FIX_DELEGATION))
}


/// The krbtgt account is disabled by design, so it is checked whatever its flags; no recorded change is reported too.
pub fn check_krbtgt_age(entry: &Entry, thresholds: &Thresholds, now: i64) -> Option<Finding> {
    let is_krbtgt = entry
        .sid
        .as_deref()
        .is_some_and(|sid| sid.starts_with(DOMAIN_SID_PREFIX) && sid.ends_with(KRBTGT_RID_SUFFIX));
    let limit = i64::from(thresholds.krbtgt_max_age_days).saturating_mul(SECONDS_PER_DAY);
    let too_old = entry.pwd_last_set.is_none_or(|changed| now.saturating_sub(changed) > limit);
    (is_krbtgt && too_old).then(|| finding(Check::KrbtgtPasswordAge, Severity::Critical, entry, REASON_KRBTGT, FIX_KRBTGT))
}


/// A SID of Administrators, Domain Admins, Schema Admins or Enterprise Admins.
pub fn is_privileged_sid(sid: &str) -> bool {
    sid == ADMINISTRATORS_SID || (sid.starts_with(DOMAIN_SID_PREFIX) && PRIVILEGED_RID_SUFFIXES.iter().any(|suffix| sid.ends_with(suffix)))
}


/// Group entries of the snapshot whose objectSid is privileged: the name of a group is never trusted, its SID is.
pub fn privileged_groups(snapshot: &Snapshot) -> Vec<&Entry> {
    snapshot
        .entries
        .iter()
        .filter(|entry| has_class(entry, CLASS_GROUP) && entry.sid.as_deref().is_some_and(is_privileged_sid))
        .collect()
}


pub fn group_keys(groups: &[&Entry]) -> BTreeSet<String> {
    groups.iter().map(|group| group.dn.to_ascii_lowercase()).collect()
}


/// The privileged groups an entry belongs to (lowercase DNs, once each).
pub fn groups_of(entry: &Entry, keys: &BTreeSet<String>) -> BTreeSet<String> {
    entry
        .member_of
        .iter()
        .map(|dn| dn.to_ascii_lowercase())
        .filter(|key| keys.contains(key))
        .collect()
}


/// Direct members per privileged group, counted in one pass over the entries.
pub fn member_counts(snapshot: &Snapshot, keys: &BTreeSet<String>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    snapshot
        .entries
        .iter()
        .flat_map(|entry| groups_of(entry, keys))
        .for_each(|key| *counts.entry(key).or_insert(0) += 1);
    counts
}


pub fn check_group_size(group: &Entry, counts: &BTreeMap<String, usize>, thresholds: &Thresholds) -> Option<Finding> {
    let members = counts.get(&group.dn.to_ascii_lowercase()).copied().unwrap_or(0);
    (members > thresholds.privileged_max_members)
        .then(|| finding(Check::PrivilegedGroupSize, Severity::Medium, group, REASON_GROUP_SIZE, FIX_GROUP_SIZE))
}


/// An enabled privileged user with no logon recorded, or none within the threshold.
pub fn check_inactive(entry: &Entry, keys: &BTreeSet<String>, thresholds: &Thresholds, now: i64) -> Option<Finding> {
    let limit = i64::from(thresholds.inactive_days).saturating_mul(SECONDS_PER_DAY);
    let stale = entry.last_logon.is_none_or(|logon| now.saturating_sub(logon) > limit);
    (is_plain_user(entry) && !groups_of(entry, keys).is_empty() && stale)
        .then(|| finding(Check::InactivePrivileged, Severity::Medium, entry, REASON_INACTIVE, FIX_INACTIVE))
}


pub fn penalty(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => PENALTY_CRITICAL,
        Severity::High => PENALTY_HIGH,
        Severity::Medium => PENALTY_MEDIUM,
        Severity::Low => PENALTY_LOW,
    }
}


/// 100 minus the penalty of every finding (critical 40, high 15, medium 5, low 1), never below 0.
pub fn score_of(findings: &[Finding]) -> u32 {
    let total = findings.iter().map(|found| penalty(found.severity)).fold(u32::MIN, u32::saturating_add);
    SCORE_MAX.saturating_sub(total)
}


/// Every check over the snapshot; findings ranked by severity (most severe first), then DN, then check.
pub fn assess(snapshot: &Snapshot, thresholds: &Thresholds, now: i64) -> Report {
    let groups = privileged_groups(snapshot);
    let keys = group_keys(&groups);
    let counts = member_counts(snapshot, &keys);
    let per_entry = snapshot.entries.iter().flat_map(|entry| {
        [
            check_kerberoastable(entry),
            check_no_preauth(entry),
            check_unconstrained_delegation(entry),
            check_krbtgt_age(entry, thresholds, now),
            check_inactive(entry, &keys, thresholds, now),
        ]
    });
    let sizes = groups.iter().map(|group| check_group_size(group, &counts, thresholds));
    let set_aside = snapshot.unreadable.iter().flat_map(unreadable_findings);
    let mut findings: Vec<Finding> = per_entry.chain(sizes).chain(set_aside).flatten().collect();
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.object.cmp(&right.object))
            .then_with(|| left.check.cmp(&right.check))
    });
    let score = score_of(&findings);
    Report { findings, score }
}
