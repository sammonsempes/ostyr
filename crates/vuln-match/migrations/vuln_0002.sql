CREATE TABLE vuln_asset_resolved (
    tenant text NOT NULL,
    asset text NOT NULL,
    resolved_total bigint NOT NULL CHECK (resolved_total >= 0),
    healed_day bigint NOT NULL CHECK (healed_day >= 0),
    PRIMARY KEY (tenant, asset)
);
INSERT INTO vuln_finding_rows (tenant, open_total, resolved_total)
SELECT tenant, count(*) FILTER (WHERE resolved_micros IS NULL), count(*) FILTER (WHERE resolved_micros IS NOT NULL)
FROM vuln_findings GROUP BY tenant
ON CONFLICT (tenant) DO NOTHING;
INSERT INTO vuln_asset_resolved (tenant, asset, resolved_total, healed_day)
SELECT tenant, asset, count(*), floor(extract(epoch FROM now()) / 86400)::bigint
FROM vuln_findings WHERE resolved_micros IS NOT NULL GROUP BY tenant, asset;
CREATE FUNCTION vuln_counters_rebuild(tenant_name text)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public SET enable_seqscan = off SET enable_bitmapscan = off SET jit = off AS $$
DECLARE
    micros_per_day CONSTANT bigint := 86400000000;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('vuln_scan_store/' || tenant_name, 0));
    IF EXISTS (SELECT 1 FROM vuln_finding_rows WHERE tenant = tenant_name) THEN
        RETURN 0;
    END IF;
    INSERT INTO vuln_asset_resolved (tenant, asset, resolved_total, healed_day)
    SELECT tenant_name, asset, count(*), floor(extract(epoch FROM clock_timestamp()) * 1000000 / micros_per_day)::bigint
    FROM vuln_findings WHERE tenant = tenant_name AND resolved_micros IS NOT NULL GROUP BY asset
    ON CONFLICT (tenant, asset) DO UPDATE SET resolved_total = EXCLUDED.resolved_total, healed_day = EXCLUDED.healed_day;
    INSERT INTO vuln_finding_rows (tenant, open_total, resolved_total)
    SELECT tenant_name, count(*) FILTER (WHERE resolved_micros IS NULL), count(*) FILTER (WHERE resolved_micros IS NOT NULL)
    FROM vuln_findings WHERE tenant = tenant_name;
    RETURN 1;
END
$$;
DROP FUNCTION vuln_scan_store(text, text, jsonb, bigint, bigint, bigint, bigint, bigint);
CREATE FUNCTION vuln_scan_store(
    tenant_name text, asset_name text, docs jsonb, max_open bigint, now_micros bigint, max_resolved bigint, granularity bigint,
    max_asset_resolved bigint,
    OUT n_inserted bigint, OUT n_updated bigint, OUT n_resolved bigint, OUT n_refused_no_room bigint, OUT n_evicted bigint, OUT n_duplicates bigint,
    OUT n_counters_missing bigint
)
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public SET enable_seqscan = off SET enable_bitmapscan = off SET jit = off AS $$
DECLARE
    room bigint;
    n_reopened bigint;
    resolved_now bigint;
    excess bigint;
    asset_evicted bigint;
    tenant_evicted bigint;
    micros_per_day CONSTANT bigint := 86400000000;
    today bigint := now_micros / micros_per_day;
    asset_resolved bigint;
    asset_before bigint;
    asset_day bigint;
    asset_row boolean;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('vuln_scan_store/' || tenant_name, 0));
    IF NOT EXISTS (SELECT 1 FROM vuln_finding_rows WHERE tenant = tenant_name) THEN
        n_inserted := 0;
        n_updated := 0;
        n_resolved := 0;
        n_refused_no_room := 0;
        n_evicted := 0;
        n_duplicates := 0;
        n_counters_missing := 1;
        RETURN;
    END IF;
    n_counters_missing := 0;
    SELECT a.resolved_total, a.healed_day INTO asset_resolved, asset_day FROM vuln_asset_resolved a WHERE a.tenant = tenant_name AND a.asset = asset_name;
    asset_row := FOUND;
    IF NOT asset_row OR asset_day <> today THEN
        SELECT count(*) INTO asset_resolved FROM vuln_findings WHERE tenant = tenant_name AND asset = asset_name AND resolved_micros IS NOT NULL;
        asset_day := today;
        asset_row := false;
    END IF;
    asset_before := asset_resolved;
    SELECT max_open - open_total INTO room FROM vuln_finding_rows WHERE tenant = tenant_name;
    WITH incoming AS (
        SELECT * FROM vuln_incoming(docs)
    ),
    matched AS (
        SELECT i.*, f.present, f.resolved_micros AS was_resolved, f.last_seen_micros AS was_seen,
            (f.installed_version, f.fixed_version, f.cvss, f.epss, f.kev, f.priority)
                IS DISTINCT FROM (i.installed_version, i.fixed_version, i.cvss, i.epss, i.kev, i.priority) AS changed
        FROM incoming i LEFT JOIN LATERAL (
            SELECT true AS present, g.resolved_micros, g.last_seen_micros, g.installed_version, g.fixed_version, g.cvss, g.epss, g.kev, g.priority
            FROM vuln_findings g
            WHERE g.tenant = tenant_name AND g.asset = asset_name AND g.ecosystem = i.ecosystem AND g.package = i.package AND g.record_id = i.record_id
            LIMIT 1
        ) f ON true
    ),
    resolved AS (
        UPDATE vuln_findings f SET resolved_micros = now_micros
        WHERE f.ctid = ANY (ARRAY(
            SELECT o.ctid FROM vuln_findings o
            WHERE o.tenant = tenant_name AND o.asset = asset_name AND o.resolved_micros IS NULL
                AND NOT EXISTS (SELECT 1 FROM incoming i WHERE i.ecosystem = o.ecosystem AND i.package = o.package AND i.record_id = o.record_id)
            ORDER BY o.ecosystem, o.package, o.record_id
        ))
        RETURNING 1
    ),
    candidates AS (
        SELECT ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, true AS is_new FROM matched WHERE present IS NULL
        UNION ALL
        SELECT ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, false FROM matched WHERE was_resolved IS NOT NULL
    ),
    admitted AS (
        SELECT * FROM candidates ORDER BY priority DESC, ecosystem, package, record_id LIMIT greatest(room + (SELECT count(*) FROM resolved), 0)
    ),
    written AS (
        INSERT INTO vuln_findings (tenant, asset, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority,
            first_seen_micros, last_seen_micros, resolved_micros)
        SELECT tenant_name, asset_name, w.ecosystem, w.package, w.record_id, w.installed_version, w.fixed_version, w.cvss, w.epss, w.kev, w.priority,
            now_micros, now_micros, NULL
        FROM (
            SELECT ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority FROM admitted
            UNION ALL
            SELECT ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority FROM matched
            WHERE was_resolved IS NULL AND present AND (changed OR was_seen <= now_micros - granularity)
        ) w
        ON CONFLICT (tenant, asset, ecosystem, package, record_id) DO UPDATE SET
            installed_version = EXCLUDED.installed_version, fixed_version = EXCLUDED.fixed_version, cvss = EXCLUDED.cvss, epss = EXCLUDED.epss,
            kev = EXCLUDED.kev, priority = EXCLUDED.priority, last_seen_micros = EXCLUDED.last_seen_micros, resolved_micros = NULL
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM admitted WHERE is_new), (SELECT count(*) FROM written) - (SELECT count(*) FROM admitted WHERE is_new),
        (SELECT count(*) FROM resolved), (SELECT count(*) FROM candidates) - (SELECT count(*) FROM admitted),
        (SELECT count(*) FROM admitted WHERE NOT is_new), jsonb_array_length(docs) - (SELECT count(*) FROM incoming)
    INTO n_inserted, n_updated, n_resolved, n_refused_no_room, n_reopened, n_duplicates;
    asset_evicted := 0;
    asset_resolved := greatest(asset_resolved + n_resolved - n_reopened, 0);
    IF n_resolved > 0 AND asset_resolved > max_asset_resolved THEN
        DELETE FROM vuln_findings WHERE ctid = ANY (ARRAY(
            SELECT ctid FROM vuln_findings WHERE tenant = tenant_name AND asset = asset_name AND resolved_micros IS NOT NULL
            ORDER BY resolved_micros DESC, ecosystem DESC, package DESC, record_id DESC OFFSET max_asset_resolved
        ));
        GET DIAGNOSTICS asset_evicted = ROW_COUNT;
        asset_resolved := greatest(asset_resolved - asset_evicted, 0);
    END IF;
    IF asset_resolved = 0 THEN
        DELETE FROM vuln_asset_resolved WHERE tenant = tenant_name AND asset = asset_name;
    ELSIF NOT asset_row OR asset_resolved <> asset_before THEN
        INSERT INTO vuln_asset_resolved (tenant, asset, resolved_total, healed_day) VALUES (tenant_name, asset_name, asset_resolved, asset_day)
        ON CONFLICT (tenant, asset) DO UPDATE SET resolved_total = EXCLUDED.resolved_total, healed_day = EXCLUDED.healed_day;
    END IF;
    UPDATE vuln_finding_rows
    SET open_total = open_total + n_inserted + n_reopened - n_resolved, resolved_total = resolved_total + n_resolved - n_reopened - asset_evicted
    WHERE tenant = tenant_name RETURNING resolved_total INTO resolved_now;
    tenant_evicted := 0;
    excess := resolved_now - max_resolved;
    IF excess > 0 THEN
        WITH gone AS (
            DELETE FROM vuln_findings WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM vuln_findings WHERE tenant = tenant_name AND resolved_micros IS NOT NULL
                ORDER BY resolved_micros, asset, ecosystem, package, record_id LIMIT excess
            )) RETURNING asset
        ),
        per_asset AS (
            SELECT g.asset, count(*) AS n FROM gone g GROUP BY g.asset
        ),
        lowered AS (
            UPDATE vuln_asset_resolved a SET resolved_total = a.resolved_total - p.n
            FROM per_asset p WHERE a.tenant = tenant_name AND a.asset = p.asset AND a.resolved_total > p.n RETURNING 1
        ),
        emptied AS (
            DELETE FROM vuln_asset_resolved a USING per_asset p WHERE a.tenant = tenant_name AND a.asset = p.asset AND a.resolved_total <= p.n RETURNING 1
        )
        SELECT count(*) INTO tenant_evicted FROM gone;
        UPDATE vuln_finding_rows SET resolved_total = resolved_total - tenant_evicted WHERE tenant = tenant_name;
    END IF;
    n_evicted := asset_evicted + tenant_evicted;
END
$$;
