CREATE TABLE compliance_state_count (
    tenant text PRIMARY KEY,
    rows bigint NOT NULL,
    reconciled_day bigint NOT NULL DEFAULT -1
);

INSERT INTO compliance_state_count (tenant, rows) SELECT tenant, count(*) FROM compliance_state GROUP BY tenant;

CREATE INDEX compliance_state_seen ON compliance_state (tenant, last_seen_micros);

DROP FUNCTION compliance_record(text, jsonb, bigint, bigint);

CREATE FUNCTION compliance_record(
    p_tenant text, p_entries jsonb, p_now bigint, p_cap bigint, p_retention bigint, p_max_expired bigint, p_granularity bigint
)
RETURNS TABLE (entry_index bigint, outcome text, first_failed text)
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $body$
DECLARE
    room bigint;
    removed bigint;
    current_rows bigint;
    today bigint := p_now / 86400000000;
    last_day bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('compliance_state/' || p_tenant, 0));
    INSERT INTO compliance_state_count (tenant, rows) VALUES (p_tenant, 0) ON CONFLICT (tenant) DO NOTHING;
    SELECT c.reconciled_day INTO last_day FROM compliance_state_count c WHERE c.tenant = p_tenant;
    IF last_day <> today THEN
        UPDATE compliance_state_count SET rows = (SELECT count(*) FROM compliance_state WHERE tenant = p_tenant), reconciled_day = today
        WHERE tenant = p_tenant;
    END IF;
    SELECT c.rows INTO current_rows FROM compliance_state_count c WHERE c.tenant = p_tenant;
    room := p_cap - current_rows;
    RETURN QUERY
    WITH input AS (
        SELECT x.idx, x.item->>'baseline' AS baseline, x.item->>'control' AS control, x.item->>'asset' AS asset, x.item->>'verdict' AS verdict
        FROM jsonb_array_elements(p_entries) WITH ORDINALITY AS x(item, idx)
    ), ranked AS (
        SELECT i.*, s.baseline IS NULL AS fresh, s.first_failed_micros AS old_first_failed
        FROM input i
        LEFT JOIN compliance_state s
            ON s.tenant = p_tenant AND s.baseline = i.baseline AND s.control = i.control AND s.asset = i.asset
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
        WHERE st.verdict <> EXCLUDED.verdict OR st.last_seen_micros < EXCLUDED.last_seen_micros - p_granularity
        RETURNING st.baseline, st.control, st.asset, st.first_failed_micros, (st.xmax = 0) AS inserted
    ), counted AS (
        UPDATE compliance_state_count SET rows = GREATEST(rows + (SELECT count(*) FROM written WHERE written.inserted), 0) WHERE tenant = p_tenant
    )
    SELECT n.idx::bigint, CASE WHEN n.fresh AND w.baseline IS NULL THEN 'refused' ELSE 'stored' END,
        coalesce(coalesce(w.first_failed_micros, n.old_first_failed)::text, '')
    FROM numbered n LEFT JOIN written w ON w.baseline = n.baseline AND w.control = n.control AND w.asset = n.asset;
    DELETE FROM compliance_state AS old
    WHERE old.tenant = p_tenant AND (old.baseline, old.control, old.asset) IN (
        SELECT e.baseline, e.control, e.asset FROM compliance_state e
        WHERE e.tenant = p_tenant AND e.last_seen_micros < p_now - p_retention - p_granularity
        ORDER BY e.last_seen_micros LIMIT p_max_expired
    );
    GET DIAGNOSTICS removed = ROW_COUNT;
    UPDATE compliance_state_count SET rows = GREATEST(rows - removed, 0) WHERE tenant = p_tenant;
END
$body$;
