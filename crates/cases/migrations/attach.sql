WITH found_case AS (
    SELECT 1 FROM cases WHERE tenant = $1 AND id = $2::text
), found_alert AS (
    SELECT 1 FROM alerts WHERE tenant = $1 AND id = $3::text
), linked AS (
    SELECT count(*) AS size FROM case_alerts WHERE tenant = $1 AND case_id = $2::text
), added AS (
    INSERT INTO case_alerts (tenant, case_id, alert_id)
    SELECT $1::text, $2::text, $3::text
    WHERE EXISTS (SELECT 1 FROM found_case) AND EXISTS (SELECT 1 FROM found_alert) AND (SELECT size FROM linked) < $4::text::bigint
    ON CONFLICT DO NOTHING
    RETURNING 1
)
SELECT (SELECT count(*) FROM found_case)::text, (SELECT count(*) FROM found_alert)::text, (SELECT count(*) FROM added)::text,
    (SELECT size FROM linked)::text
