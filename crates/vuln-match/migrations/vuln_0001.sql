CREATE TABLE vuln_findings (
    tenant text NOT NULL,
    asset text NOT NULL,
    ecosystem text NOT NULL,
    package text NOT NULL,
    record_id text NOT NULL,
    installed_version text NOT NULL,
    fixed_version text,
    cvss double precision NOT NULL CHECK (cvss >= 0 AND cvss <= 10),
    epss double precision NOT NULL CHECK (epss >= 0 AND epss <= 1),
    kev boolean NOT NULL,
    priority bigint NOT NULL CHECK (priority >= 0),
    first_seen_micros bigint NOT NULL CHECK (first_seen_micros >= 0),
    last_seen_micros bigint NOT NULL CHECK (last_seen_micros >= 0),
    resolved_micros bigint CHECK (resolved_micros >= 0),
    PRIMARY KEY (tenant, asset, ecosystem, package, record_id)
);
CREATE INDEX vuln_findings_open ON vuln_findings (tenant, priority DESC, asset, ecosystem, package, record_id) WHERE resolved_micros IS NULL;
CREATE INDEX vuln_findings_resolved ON vuln_findings (tenant, resolved_micros, asset, ecosystem, package, record_id) WHERE resolved_micros IS NOT NULL;
CREATE INDEX vuln_findings_open_asset ON vuln_findings (tenant, asset, ecosystem, package, record_id) WHERE resolved_micros IS NULL;
CREATE INDEX vuln_findings_resolved_asset ON vuln_findings (tenant, asset, resolved_micros, ecosystem, package, record_id) WHERE resolved_micros IS NOT NULL;
CREATE TABLE vuln_finding_rows (
    tenant text PRIMARY KEY,
    open_total bigint NOT NULL CHECK (open_total >= 0),
    resolved_total bigint NOT NULL CHECK (resolved_total >= 0)
);
CREATE FUNCTION vuln_incoming(docs jsonb)
RETURNS TABLE (ecosystem text, package text, record_id text, installed_version text, fixed_version text, cvss double precision, epss double precision,
    kev boolean, priority bigint)
LANGUAGE plpgsql STABLE ROWS 50000 SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
BEGIN
    RETURN QUERY
    SELECT DISTINCT ON (d.ecosystem, d.package, d.record_id) d.ecosystem, d.package, d.record_id, d.installed_version, d.fixed_version,
        d.cvss, d.epss, d.kev, d.priority
    FROM jsonb_to_recordset(docs) AS d (
        ecosystem text, package text, record_id text, installed_version text, fixed_version text,
        cvss double precision, epss double precision, kev boolean, priority bigint
    )
    ORDER BY d.ecosystem, d.package, d.record_id, d.priority DESC, d.installed_version, d.fixed_version NULLS FIRST, d.cvss, d.epss, d.kev;
END
$$;
CREATE FUNCTION vuln_scan_store(
    tenant_name text, asset_name text, docs jsonb, max_open bigint, now_micros bigint, max_resolved bigint, granularity bigint,
    max_asset_resolved bigint,
    OUT n_inserted bigint, OUT n_updated bigint, OUT n_resolved bigint, OUT n_refused_no_room bigint, OUT n_evicted bigint
)
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public SET enable_seqscan = off SET enable_bitmapscan = off SET jit = off AS $$
DECLARE
    room bigint;
    n_reopened bigint;
    resolved_now bigint;
    excess bigint;
    asset_evicted bigint;
    tenant_evicted bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('vuln_scan_store/' || tenant_name, 0));
    IF NOT EXISTS (SELECT 1 FROM vuln_finding_rows WHERE tenant = tenant_name) THEN
        INSERT INTO vuln_finding_rows (tenant, open_total, resolved_total)
        SELECT tenant_name, count(*) FILTER (WHERE resolved_micros IS NULL), count(*) FILTER (WHERE resolved_micros IS NOT NULL)
        FROM vuln_findings WHERE tenant = tenant_name;
    END IF;
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
        (SELECT count(*) FROM admitted WHERE NOT is_new)
    INTO n_inserted, n_updated, n_resolved, n_refused_no_room, n_reopened;
    asset_evicted := 0;
    IF n_resolved > 0 THEN
        DELETE FROM vuln_findings WHERE ctid = ANY (ARRAY(
            SELECT ctid FROM vuln_findings WHERE tenant = tenant_name AND asset = asset_name AND resolved_micros IS NOT NULL
            ORDER BY resolved_micros DESC, ecosystem DESC, package DESC, record_id DESC OFFSET max_asset_resolved
        ));
        GET DIAGNOSTICS asset_evicted = ROW_COUNT;
    END IF;
    UPDATE vuln_finding_rows
    SET open_total = open_total + n_inserted + n_reopened - n_resolved, resolved_total = resolved_total + n_resolved - n_reopened - asset_evicted
    WHERE tenant = tenant_name RETURNING resolved_total INTO resolved_now;
    tenant_evicted := 0;
    excess := resolved_now - max_resolved;
    IF excess > 0 THEN
        DELETE FROM vuln_findings WHERE ctid = ANY (ARRAY(
            SELECT ctid FROM vuln_findings WHERE tenant = tenant_name AND resolved_micros IS NOT NULL
            ORDER BY resolved_micros, asset, ecosystem, package, record_id LIMIT excess
        ));
        GET DIAGNOSTICS tenant_evicted = ROW_COUNT;
        UPDATE vuln_finding_rows SET resolved_total = resolved_total - tenant_evicted WHERE tenant = tenant_name;
    END IF;
    n_evicted := asset_evicted + tenant_evicted;
END
$$;
