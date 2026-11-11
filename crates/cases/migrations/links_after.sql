SELECT cases.id, COALESCE(case_alerts.alert_id, '')
FROM cases LEFT JOIN case_alerts ON case_alerts.tenant = cases.tenant AND case_alerts.case_id = cases.id AND case_alerts.alert_id > $3::text
WHERE cases.tenant = $1 AND cases.id = $2::text
ORDER BY case_alerts.alert_id LIMIT $4::text::bigint
