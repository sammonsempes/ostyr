use crate::error::OncallError;
use crate::limits::{MAX_ALERTS, MAX_GROUP_LABELS};
use crate::model::{Alert, AlertGroup};
use crate::validate::check_between;
use std::collections::{BTreeMap, BTreeSet};


/// Keeps the first alert of each fingerprint, then groups by the values of `group_by` (a missing label groups as empty).
pub fn group_alerts(alerts: &[Alert], group_by: &[String]) -> Result<Vec<AlertGroup>, OncallError> {
    check_between("alerts", alerts.len() as u64, 0, MAX_ALERTS)?;
    check_between("group_by", group_by.len() as u64, 0, MAX_GROUP_LABELS)?;
    let mut seen = BTreeSet::new();
    let groups = alerts.iter().filter(|alert| seen.insert(alert.fingerprint.as_str())).fold(
        BTreeMap::<BTreeMap<String, String>, Vec<Alert>>::new(),
        |mut by_key, alert| {
            let key = group_by
                .iter()
                .map(|label| (label.clone(), alert.labels.get(label).map_or_else(String::new, Clone::clone)))
                .collect();
            by_key.entry(key).or_default().push(alert.clone());
            by_key
        },
    );
    Ok(groups
        .into_iter()
        .map(|(labels, members)| AlertGroup { labels, alerts: members })
        .collect())
}
