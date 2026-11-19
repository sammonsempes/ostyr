CREATE TABLE compliance_state (
    tenant text NOT NULL,
    baseline text NOT NULL,
    control text NOT NULL,
    asset text NOT NULL,
    verdict text NOT NULL CHECK (verdict IN ('pass', 'fail', 'error', 'excepted')),
    first_failed_micros bigint,
    last_seen_micros bigint NOT NULL,
    PRIMARY KEY (tenant, baseline, control, asset),
    CHECK ((verdict = 'fail') = (first_failed_micros IS NOT NULL))
);

CREATE FUNCTION compliance_record(p_tenant text, p_entries jsonb, p_now bigint, p_cap bigint)
RETURNS TABLE (entry_index bigint, outcome text, first_failed text)
LANGUAGE plpgsql AS $body$
DECLARE
    room bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('compliance_state'), hashtext(p_tenant));
    SELECT p_cap - count(*) INTO room FROM compliance_state WHERE tenant = p_tenant;
    RETURN QUERY
    WITH input AS (
        SELECT x.idx, x.item->>'baseline' AS baseline, x.item->>'control' AS control, x.item->>'asset' AS asset, x.item->>'verdict' AS verdict
        FROM jsonb_array_elements(p_entries) WITH ORDINALITY AS x(item, idx)
    ), ranked AS (
        SELECT i.*, NOT EXISTS (
            SELECT 1 FROM compliance_state s
            WHERE s.tenant = p_tenant AND s.baseline = i.baseline AND s.control = i.control AND s.asset = i.asset
        ) AS fresh
        FROM input i
    ), numbered AS (
        SELECT r.*, count(*) FILTER (WHERE r.fresh) OVER (ORDER BY r.idx) AS fresh_rank FROM ranked r
    ), written AS (
        INSERT INTO compliance_state AS st (tenant, baseline, control, asset, verdict, first_failed_micros, last_seen_micros)
        SELECT p_tenant, n.baseline, n.control, n.asset, n.verdict, CASE WHEN n.verdict = 'fail' THEN p_now END, p_now
        FROM numbered n WHERE NOT n.fresh OR n.fresh_rank <= room
        ON CONFLICT (tenant, baseline, control, asset) DO UPDATE SET
            first_failed_micros = CASE
                WHEN EXCLUDED.verdict <> 'fail' THEN NULL
                WHEN st.verdict = 'fail' THEN st.first_failed_micros
                ELSE EXCLUDED.first_failed_micros
            END,
            verdict = EXCLUDED.verdict,
            last_seen_micros = EXCLUDED.last_seen_micros
        RETURNING st.baseline, st.control, st.asset, st.first_failed_micros
    )
    SELECT n.idx::bigint, CASE WHEN w.baseline IS NULL THEN 'refused' ELSE 'stored' END, coalesce(w.first_failed_micros::text, '')
    FROM numbered n LEFT JOIN written w ON w.baseline = n.baseline AND w.control = n.control AND w.asset = n.asset;
END
$body$;
