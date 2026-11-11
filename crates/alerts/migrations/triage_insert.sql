WITH found AS (
    SELECT id FROM alerts WHERE tenant = $1 AND id = $2::text
), written AS (
    INSERT INTO alert_triage (tenant, alert_id, status, actor, note, updated_at, version)
    SELECT $1::text, id, $3::text, $4::text, NULLIF($5::text, ''), $6::text::bigint, 1 FROM found
    ON CONFLICT (tenant, alert_id) DO NOTHING
    RETURNING version
)
SELECT (SELECT count(*) FROM found)::text, COALESCE((SELECT version FROM written)::text, '')
