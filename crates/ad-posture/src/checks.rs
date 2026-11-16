use crate::model::{BoundHit, Check, Entry, Finding, Report, Severity, Snapshot, Thresholds, Unreadable};
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


/// Classes of the domain object whose `objectSid` is the domain SID.
pub const DOMAIN_CLASSES: [&str; 2] = ["domainDNS", "domain"];


pub const DOMAIN_ADMINS_RID_SUFFIX: &str = "-512";


pub const OBJECT_SNAPSHOT: &str = "snapshot";


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


pub const REASON_BOUND: &str = "a global bound of the snapshot was reached, so it was not assessed: treat this as an incident";


pub const FIX_BOUND: &str = "export the privileged principals first, look for a principal that created objects in bulk, then export again";


pub const REASON_NO_DOMAIN: &str = "the domain SID could not be determined, so krbtgt and the privileged groups were not assessed";


pub const FIX_NO_DOMAIN: &str = "export the domain object (domainDNS) with its objectSid, then export again";


pub const REASON_DROPPED: &str = "values of a list were refused or over its count and were left out of the checks that read them";


pub const FIX_DROPPED: &str = "inspect the objects that point at this entry on the domain controller: another principal may have written them";


pub const REASON_INCOMPLETE_KERBEROAST: &str = "the Kerberoastable check is incomplete: servicePrincipalName or objectClass could not be fully read";


pub const REASON_INCOMPLETE_INACTIVE: &str = "the inactive privileged check is incomplete: memberOf or objectClass could not be fully read";


pub const REASON_INCOMPLETE_GROUP_SIZE: &str = "the privileged group size is incomplete: memberOf of some entries could not be fully read";


pub const FIX_INCOMPLETE: &str = "inspect the unreadable values on the domain controller, then export again";


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


/// True when a list of the entry has a gap: a value was refused or the list was over its count.
pub fn has_gap(entry: &Entry, fields: &[&str]) -> bool {
    entry.gaps.iter().any(|gap| fields.contains(&gap.field))
}


/// A list over its count keeps no value, so a check that reads it cannot decide; refused values alone leave the others readable.
pub fn has_over_limit(entry: &Entry, fields: &[&str]) -> bool {
    entry.gaps.iter().any(|gap| gap.over_limit && fields.contains(&gap.field))
}


/// The gaps of an entry as text built from field names and numbers only.
pub fn gap_detail(entry: &Entry) -> String {
    entry
        .gaps
        .iter()
        .map(|gap| {
            let limit = if gap.over_limit { " (list over its count, none kept)" } else { "" };
            format!("{} dropped {}{limit}", gap.field, gap.dropped)
        })
        .collect::<Vec<String>>()
        .join("; ")
}


pub fn finding_of(check: Check, severity: Severity, object: String, texts: (&'static str, &'static str), detail: String) -> Finding {
    Finding {
        severity,
        check,
        object,
        reason: texts.0,
        fix: texts.1,
        detail,
    }
}


pub fn finding(check: Check, severity: Severity, entry: &Entry, reason: &'static str, fix: &'static str) -> Finding {
    finding_of(check, severity, entry.dn.clone(), (reason, fix), String::new())
}


/// Names an unreadable entry by position, field, fixed reason, DN digest and, when readable, account name and SID: never by the DN text.
pub fn unreadable_object(item: &Unreadable) -> String {
    let account = item.account.as_ref().map_or_else(String::new, |name| format!(" account {name}"));
    let sid = item.sid.as_ref().map_or_else(String::new, |text| format!(" sid {text}"));
    format!(
        "entry {} field {} reason {} dn-sha256 {}{account}{sid}",
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
            (REASON_UNREADABLE, FIX_UNREADABLE),
            String::new(),
        )),
        item.group_risk.then(|| {
            finding_of(
                Check::PrivilegedGroupUnreadable,
                Severity::Critical,
                unreadable_object(item),
                (REASON_GROUP_UNREADABLE, FIX_GROUP_UNREADABLE),
                String::new(),
            )
        }),
    ]
}


/// A global bound that was reached is Critical: an attacker that can create objects can push the snapshot over it.
pub fn bound_finding(hit: &BoundHit) -> Finding {
    finding_of(
        Check::AssessmentIncomplete,
        Severity::Critical,
        OBJECT_SNAPSHOT.to_owned(),
        (REASON_BOUND, FIX_BOUND),
        format!("bound {} observed {} limit {}", hit.bound, hit.observed, hit.limit),
    )
}


/// True when `sid` is the domain SID followed by `suffix`.
pub fn is_domain_rid(sid: &str, domain: &str, suffix: &str) -> bool {
    sid.strip_prefix(domain).is_some_and(|rest| rest == suffix)
}


/// SIDs of the domain objects (class `domainDNS` or `domain`).
pub fn domain_object_sids(snapshot: &Snapshot) -> BTreeSet<String> {
    snapshot
        .entries
        .iter()
        .filter(|entry| DOMAIN_CLASSES.iter().any(|class| has_class(entry, class)))
        .filter_map(|entry| entry.sid.clone())
        .filter(|sid| sid.starts_with(DOMAIN_SID_PREFIX))
        .collect()
}


/// The part of the SID of every entry of `class` that comes before `rid_suffix`.
pub fn prefixes_of(snapshot: &Snapshot, class: &str, rid_suffix: &str) -> BTreeSet<String> {
    snapshot
        .entries
        .iter()
        .filter(|entry| has_class(entry, class))
        .filter_map(|entry| entry.sid.as_deref())
        .filter(|sid| sid.starts_with(DOMAIN_SID_PREFIX))
        .filter_map(|sid| sid.strip_suffix(rid_suffix))
        .map(str::to_owned)
        .collect()
}


/// The domain SID: the `objectSid` of the domain object; else the prefix of the RID 512 group; else the prefix of the RID 502 user; `None` when ambiguous.
pub fn domain_sid(snapshot: &Snapshot) -> Option<String> {
    let mut ordered = [
        domain_object_sids(snapshot),
        prefixes_of(snapshot, CLASS_GROUP, DOMAIN_ADMINS_RID_SUFFIX),
        prefixes_of(snapshot, CLASS_USER, KRBTGT_RID_SUFFIX),
    ]
    .into_iter()
    .find(|candidates| !candidates.is_empty())
    .into_iter()
    .flatten();
    match (ordered.next(), ordered.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}


/// True when the entry is the krbtgt account of the domain: a user of that domain with RID 502 (a foreign security principal is not one).
pub fn is_krbtgt(entry: &Entry, domain: Option<&str>) -> bool {
    has_class(entry, CLASS_USER)
        && entry
            .sid
            .as_deref()
            .is_some_and(|sid| domain.is_some_and(|found| is_domain_rid(sid, found, KRBTGT_RID_SUFFIX)))
}


/// A SID of Administrators, or a group of the domain with the RID of Domain Admins, Schema Admins or Enterprise Admins.
pub fn is_domain_privileged(sid: &str, domain: Option<&str>) -> bool {
    sid == ADMINISTRATORS_SID || domain.is_some_and(|found| PRIVILEGED_RID_SUFFIXES.iter().any(|suffix| is_domain_rid(sid, found, suffix)))
}


/// The same SIDs without a domain: every domain-shaped RID counts. Used only to flag a refused entry, where over-reporting is the safe side.
pub fn is_privileged_sid(sid: &str) -> bool {
    sid == ADMINISTRATORS_SID || (sid.starts_with(DOMAIN_SID_PREFIX) && PRIVILEGED_RID_SUFFIXES.iter().any(|suffix| sid.ends_with(suffix)))
}


/// Group entries of the snapshot whose objectSid is privileged in the domain: the name of a group is never trusted, its SID is.
pub fn privileged_groups<'a>(snapshot: &'a Snapshot, domain: Option<&str>) -> Vec<&'a Entry> {
    snapshot
        .entries
        .iter()
        .filter(|entry| has_class(entry, CLASS_GROUP) && entry.sid.as_deref().is_some_and(|sid| is_domain_privileged(sid, domain)))
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


/// Critical when the entry is krbtgt, a privileged group, or a member of one by the values that could be read.
pub fn incomplete_severity(entry: &Entry, domain: Option<&str>, keys: &BTreeSet<String>) -> Severity {
    let is_group = has_class(entry, CLASS_GROUP) && entry.sid.as_deref().is_some_and(|sid| is_domain_privileged(sid, domain));
    if is_krbtgt(entry, domain) || is_group || !groups_of(entry, keys).is_empty() {
        Severity::Critical
    } else {
        Severity::High
    }
}


/// One Low finding per entry with a gap, naming the entry and the counts.
pub fn check_dropped(entry: &Entry) -> Option<Finding> {
    (!entry.gaps.is_empty()).then(|| {
        finding_of(
            Check::DroppedValues,
            Severity::Low,
            entry.dn.clone(),
            (REASON_DROPPED, FIX_DROPPED),
            gap_detail(entry),
        )
    })
}


/// An enabled user (a computer is not one) with a service principal name: a refused or over-count value still proves one exists.
pub fn check_kerberoastable(entry: &Entry) -> Option<Finding> {
    (is_plain_user(entry) && (!entry.spns.is_empty() || has_gap(entry, &["servicePrincipalName"]))).then(|| {
        finding_of(
            Check::Kerberoastable,
            Severity::High,
            entry.dn.clone(),
            (REASON_KERBEROASTABLE, FIX_KERBEROASTABLE),
            gap_detail(entry),
        )
    })
}


/// The Kerberoastable check could not decide: an enabled account that is not known to be a computer has an unknown class (a refused `objectClass` value).
pub fn check_incomplete_kerberoast(entry: &Entry, domain: Option<&str>, keys: &BTreeSet<String>) -> Option<Finding> {
    (is_enabled(entry) && !has_class(entry, CLASS_COMPUTER) && has_gap(entry, &["objectClass"]) && check_kerberoastable(entry).is_none()).then(|| {
        finding_of(
            Check::IncompleteCheck,
            incomplete_severity(entry, domain, keys),
            entry.dn.clone(),
            (REASON_INCOMPLETE_KERBEROAST, FIX_INCOMPLETE),
            gap_detail(entry),
        )
    })
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
pub fn check_krbtgt_age(entry: &Entry, domain: Option<&str>, thresholds: &Thresholds, now: i64) -> Option<Finding> {
    let limit = i64::from(thresholds.krbtgt_max_age_days).saturating_mul(SECONDS_PER_DAY);
    let too_old = entry.pwd_last_set.is_none_or(|changed| now.saturating_sub(changed) > limit);
    (is_krbtgt(entry, domain) && too_old).then(|| finding(Check::KrbtgtPasswordAge, Severity::Critical, entry, REASON_KRBTGT, FIX_KRBTGT))
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


/// Above the threshold: Medium. At or below it, while `incomplete_entries` entries have a `memberOf` list over its count: Critical, the size is only a lower bound.
pub fn check_group_size(group: &Entry, counts: &BTreeMap<String, usize>, thresholds: &Thresholds, incomplete_entries: usize) -> Option<Finding> {
    let members = counts.get(&group.dn.to_ascii_lowercase()).copied().unwrap_or(0);
    if members > thresholds.privileged_max_members {
        Some(finding(
            Check::PrivilegedGroupSize,
            Severity::Medium,
            group,
            REASON_GROUP_SIZE,
            FIX_GROUP_SIZE,
        ))
    } else if incomplete_entries > 0 {
        Some(finding_of(
            Check::IncompleteCheck,
            Severity::Critical,
            group.dn.clone(),
            (REASON_INCOMPLETE_GROUP_SIZE, FIX_INCOMPLETE),
            format!("memberOf of {incomplete_entries} entries is over its count"),
        ))
    } else {
        None
    }
}


pub fn is_stale(entry: &Entry, thresholds: &Thresholds, now: i64) -> bool {
    let limit = i64::from(thresholds.inactive_days).saturating_mul(SECONDS_PER_DAY);
    entry.last_logon.is_none_or(|logon| now.saturating_sub(logon) > limit)
}


/// An enabled privileged user with no logon recorded, or none within the threshold.
pub fn check_inactive(entry: &Entry, keys: &BTreeSet<String>, thresholds: &Thresholds, now: i64) -> Option<Finding> {
    (is_plain_user(entry) && !groups_of(entry, keys).is_empty() && is_stale(entry, thresholds, now))
        .then(|| finding(Check::InactivePrivileged, Severity::Medium, entry, REASON_INACTIVE, FIX_INACTIVE))
}


/// The inactive check could not decide: a stale enabled account that is not known to be a computer has a gap in `memberOf` or `objectClass`.
pub fn check_incomplete_inactive(entry: &Entry, domain: Option<&str>, keys: &BTreeSet<String>, thresholds: &Thresholds, now: i64) -> Option<Finding> {
    (is_enabled(entry)
        && !has_class(entry, CLASS_COMPUTER)
        && (has_over_limit(entry, &["memberOf"]) || has_gap(entry, &["objectClass"]))
        && is_stale(entry, thresholds, now)
        && check_inactive(entry, keys, thresholds, now).is_none())
    .then(|| {
        finding_of(
            Check::IncompleteCheck,
            incomplete_severity(entry, domain, keys),
            entry.dn.clone(),
            (REASON_INCOMPLETE_INACTIVE, FIX_INCOMPLETE),
            gap_detail(entry),
        )
    })
}


/// A snapshot with a privileged-looking SID but no determinable domain cannot have krbtgt and its groups assessed.
pub fn check_domain_missing(snapshot: &Snapshot, domain: Option<&str>) -> Option<Finding> {
    let privileged_looking = snapshot.entries.iter().any(|entry| is_krbtgt_shaped(entry) || is_group_shaped(entry));
    (domain.is_none() && privileged_looking).then(|| {
        finding_of(
            Check::AssessmentIncomplete,
            Severity::Critical,
            OBJECT_SNAPSHOT.to_owned(),
            (REASON_NO_DOMAIN, FIX_NO_DOMAIN),
            "domain SID missing or ambiguous".to_owned(),
        )
    })
}


/// A group of any domain with a privileged domain RID.
pub fn is_group_shaped(entry: &Entry) -> bool {
    has_class(entry, CLASS_GROUP)
        && entry
            .sid
            .as_deref()
            .is_some_and(|sid| sid.starts_with(DOMAIN_SID_PREFIX) && is_privileged_sid(sid))
}


/// A user SID that ends with the krbtgt RID, in any domain.
pub fn is_krbtgt_shaped(entry: &Entry) -> bool {
    has_class(entry, CLASS_USER)
        && entry
            .sid
            .as_deref()
            .is_some_and(|sid| sid.starts_with(DOMAIN_SID_PREFIX) && sid.ends_with(KRBTGT_RID_SUFFIX))
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


/// Every check over the snapshot; an incomplete assessment (a bound hit, no determinable domain) has no score; findings ranked by severity (most severe first), then DN, then check.
pub fn assess(snapshot: &Snapshot, thresholds: &Thresholds, now: i64) -> Report {
    let domain = domain_sid(snapshot);
    let groups = privileged_groups(snapshot, domain.as_deref());
    let keys = group_keys(&groups);
    let counts = member_counts(snapshot, &keys);
    let incomplete_entries = snapshot.entries.iter().filter(|entry| has_over_limit(entry, &["memberOf"])).count();
    let per_entry = snapshot.entries.iter().flat_map(|entry| {
        [
            check_kerberoastable(entry),
            check_incomplete_kerberoast(entry, domain.as_deref(), &keys),
            check_no_preauth(entry),
            check_unconstrained_delegation(entry),
            check_krbtgt_age(entry, domain.as_deref(), thresholds, now),
            check_inactive(entry, &keys, thresholds, now),
            check_incomplete_inactive(entry, domain.as_deref(), &keys, thresholds, now),
            check_dropped(entry),
        ]
    });
    let sizes = groups
        .iter()
        .map(|group| check_group_size(group, &counts, thresholds, incomplete_entries));
    let set_aside = snapshot.unreadable.iter().flat_map(unreadable_findings);
    let bounds = snapshot.bounds.iter().map(|hit| Some(bound_finding(hit)));
    let missing = check_domain_missing(snapshot, domain.as_deref());
    let complete = snapshot.bounds.is_empty() && missing.is_none();
    let mut findings: Vec<Finding> = per_entry
        .chain(sizes)
        .chain(set_aside)
        .chain(bounds)
        .chain(std::iter::once(missing))
        .flatten()
        .collect();
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.object.cmp(&right.object))
            .then_with(|| left.check.cmp(&right.check))
    });
    let score = complete.then(|| score_of(&findings));
    Report { findings, score }
}
