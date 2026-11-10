WITH incoming AS (
    SELECT * FROM jsonb_to_recordset($2::text::jsonb) AS doc(
        id text, rule_id text, rule_title text, severity text, event_time text, created bigint,
        host_name text, user_name text, event_ids jsonb, summary text, summary_truncated boolean, summary_original_bytes bigint
    )
), written AS (
    INSERT INTO alerts (
        tenant, id, rule_id, rule_title, severity, event_time, created,
        host_name, user_name, event_ids, summary, summary_truncated, summary_original_bytes
    )
    SELECT $1::text, id, rule_id, rule_title, severity, event_time, created,
        host_name, user_name, event_ids, summary, summary_truncated, summary_original_bytes
    FROM incoming
    ON CONFLICT (tenant, id) DO NOTHING
    RETURNING id
)
SELECT count(*)::text FROM written
