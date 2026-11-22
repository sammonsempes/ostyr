CREATE FUNCTION vuln_kev_indicator(
    tenant_name text, now_micros bigint,
    OUT figure text, OUT n_open bigint, OUT n_resolved bigint, OUT n_cleared bigint, OUT n_bad bigint, OUT n_over_30 bigint,
    OUT oldest_open_days bigint, OUT observed_micros text, OUT database_seconds text
)
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET enable_sort = off SET jit = off AS $$
WITH population AS (
    SELECT f.kev, f.first_seen_micros AS first_seen, f.last_seen_micros AS last_seen, f.resolved_micros AS resolved
    FROM vuln_findings f
    WHERE f.tenant = tenant_name AND f.kev_since_micros IS NOT NULL AND f.resolved_micros IS NULL
    UNION ALL
    SELECT f.kev, f.first_seen_micros, f.last_seen_micros, f.resolved_micros
    FROM vuln_findings f
    WHERE f.tenant = tenant_name AND f.kev_since_micros IS NOT NULL AND f.resolved_micros >= now_micros - 7776000000000
),
timed AS (
    SELECT p.kev, p.first_seen, p.resolved,
        (p.first_seen > now_micros OR p.last_seen > now_micros OR p.resolved > now_micros OR p.last_seen < p.first_seen
            OR p.resolved < p.first_seen OR p.resolved < p.last_seen) IS TRUE AS bad
    FROM population p
),
worth AS (
    SELECT t.kev, t.first_seen, t.resolved, t.bad,
        CASE
            WHEN t.bad THEN greatest(7776000000000, CASE WHEN t.first_seen <= now_micros THEN now_micros - t.first_seen ELSE 0 END)
            WHEN t.resolved IS NOT NULL THEN t.resolved - t.first_seen
            ELSE now_micros - t.first_seen
        END AS micros
    FROM timed t
),
open_seen AS (
    SELECT min(o.last_seen_micros) AS oldest
    FROM vuln_findings o
    WHERE o.tenant = tenant_name AND o.resolved_micros IS NULL
        AND o.first_seen_micros <= now_micros AND o.last_seen_micros <= now_micros AND o.last_seen_micros >= o.first_seen_micros
)
SELECT
    CASE WHEN count(*) = 0 THEN '0' ELSE round(sum(w.micros) / count(*) / 86400000000, 6)::text END,
    count(*) FILTER (WHERE w.resolved IS NULL AND NOT w.bad),
    count(*) FILTER (WHERE w.resolved IS NOT NULL AND NOT w.bad),
    count(*) FILTER (WHERE NOT w.kev),
    count(*) FILTER (WHERE w.bad),
    count(*) FILTER (WHERE w.resolved IS NULL AND NOT w.bad AND now_micros - w.first_seen > 2592000000000),
    coalesce(max(now_micros - w.first_seen) FILTER (WHERE w.resolved IS NULL AND NOT w.bad) / 86400000000, 0),
    coalesce(
        (
            coalesce(
                (SELECT s.oldest FROM open_seen s),
                (SELECT r.resolved_micros FROM vuln_findings r
                    WHERE r.tenant = tenant_name AND r.resolved_micros IS NOT NULL
                        AND r.first_seen_micros <= now_micros AND r.last_seen_micros <= now_micros AND r.resolved_micros <= now_micros
                        AND r.last_seen_micros >= r.first_seen_micros AND r.resolved_micros >= r.first_seen_micros
                        AND r.resolved_micros >= r.last_seen_micros
                    ORDER BY r.resolved_micros DESC LIMIT 1)
            )
        )::text,
        ''
    ),
    extract(epoch from statement_timestamp())::bigint::text
FROM worth w
$$;
