WITH found AS (
    SELECT id FROM alerts WHERE tenant = $1 AND id = $2::text
), written AS (
    UPDATE alert_triage SET status = $3::text, actor = $4::text, note = NULLIF($5::text, ''), updated_at = $6::text::bigint, version = version + 1
    WHERE tenant = $1 AND alert_id = $2::text AND version = $7::text::bigint
    RETURNING version
)
SELECT (SELECT count(*) FROM found)::text, COALESCE((SELECT version FROM written)::text, '')
