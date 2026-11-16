use crate::error::GroupError;
use crate::model::{Group, GroupKey, GroupLimits, Progress, Work};
use crate::types::OpenGroups;
use alerts::model::{Alert, Severity};


pub const RANK_INFORMATIONAL: u8 = 0;


pub const RANK_LOW: u8 = 1;


pub const RANK_MEDIUM: u8 = 2;


pub const RANK_HIGH: u8 = 3;


pub const RANK_CRITICAL: u8 = 4;


pub fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Informational => RANK_INFORMATIONAL,
        Severity::Low => RANK_LOW,
        Severity::Medium => RANK_MEDIUM,
        Severity::High => RANK_HIGH,
        Severity::Critical => RANK_CRITICAL,
    }
}


pub fn key_of(alert: &Alert) -> GroupKey {
    GroupKey {
        tenant: alert.tenant.clone(),
        rule_id: alert.rule_id.clone(),
        host_name: alert.host_name.clone(),
        user_name: alert.user_name.clone(),
    }
}


pub fn event_set(alert: &Alert) -> Vec<&str> {
    let mut ids: Vec<&str> = alert.event_ids.iter().map(String::as_str).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}


pub fn new_work(key: GroupKey, alert: &Alert, sequence: u64) -> Work<'_> {
    Work {
        group: Group {
            key,
            representative: alert.id.clone(),
            alert_ids: Vec::new(),
            omitted: false,
            alert_count: 0,
            duplicates: 0,
            first_micros: alert.created_micros,
            last_micros: alert.created_micros,
            max_severity: alert.severity,
        },
        sequence,
        seen: Default::default(),
    }
}


pub fn absorb<'alerts>(work: &mut Work<'alerts>, alert: &'alerts Alert, max_alerts_per_group: usize) {
    let group = &mut work.group;
    group.alert_count += 1;
    group.last_micros = alert.created_micros;
    group.duplicates += u64::from(!work.seen.insert(event_set(alert)));
    if group.alert_ids.len() < max_alerts_per_group {
        group.alert_ids.push(alert.id.clone());
    } else {
        group.omitted = true;
    }
    if severity_rank(alert.severity) > severity_rank(group.max_severity) {
        group.max_severity = alert.severity;
        group.representative = alert.id.clone();
    }
}


pub fn is_expired(open: &OpenGroups<'_>, key: &GroupKey, created_micros: u64, window_micros: u64) -> bool {
    open.get(key)
        .is_some_and(|work| created_micros.saturating_sub(work.group.last_micros) > window_micros)
}


pub fn add_alert<'alerts>(progress: &mut Progress<'alerts>, alert: &'alerts Alert, limits: &GroupLimits) -> Result<(), GroupError> {
    let key = key_of(alert);
    if is_expired(&progress.open, &key, alert.created_micros, limits.window_micros) {
        progress.finished.extend(progress.open.remove(&key));
    }
    let is_new = !progress.open.contains_key(&key);
    let total = progress.finished.len() + progress.open.len();
    (!is_new || total < limits.max_groups)
        .then_some(())
        .ok_or(GroupError::TooManyGroups { max: limits.max_groups })?;
    let sequence = progress.next_sequence;
    progress.next_sequence += u64::from(is_new);
    let work = progress.open.entry(key.clone()).or_insert_with(|| new_work(key, alert, sequence));
    absorb(work, alert, limits.max_alerts_per_group);
    Ok(())
}


/// Groups are ordered by (tenant, first alert time, first alert id); the result does not depend on the input order.
pub fn group_alerts(alerts: &[Alert], limits: &GroupLimits) -> Result<Vec<Group>, GroupError> {
    (alerts.len() <= limits.max_alerts).then_some(()).ok_or(GroupError::TooManyAlerts {
        count: alerts.len(),
        max: limits.max_alerts,
    })?;
    let mut ordered: Vec<&Alert> = alerts.iter().collect();
    ordered.sort_by(|left, right| (&left.tenant, left.created_micros, &left.id).cmp(&(&right.tenant, right.created_micros, &right.id)));
    let mut progress = Progress::default();
    ordered.into_iter().try_for_each(|alert| add_alert(&mut progress, alert, limits))?;
    let mut works = progress.finished;
    works.extend(progress.open.into_values());
    works.sort_by_key(|work| work.sequence);
    Ok(works.into_iter().map(|work| work.group).collect())
}
