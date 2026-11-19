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
CREATE TABLE vuln_finding_rows (
    tenant text PRIMARY KEY,
    open_total bigint NOT NULL CHECK (open_total >= 0),
    resolved_total bigint NOT NULL CHECK (resolved_total >= 0)
);
CREATE FUNCTION vuln_scan_store(
    tenant_name text, asset_name text, docs jsonb, max_open bigint, now_micros bigint, max_resolved bigint, granularity bigint,
    OUT n_inserted bigint, OUT n_updated bigint, OUT n_resolved bigint, OUT n_refused_no_room bigint, OUT n_evicted bigint
)
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public SET enable_nestloop = off AS $$
DECLARE
    room bigint;
    n_reopened bigint;
    resolved_now bigint;
    excess bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('vuln_scan_store/' || tenant_name, 0));
    IF NOT EXISTS (SELECT 1 FROM vuln_finding_rows WHERE tenant = tenant_name) THEN
        INSERT INTO vuln_finding_rows (tenant, open_total, resolved_total)
        SELECT tenant_name, count(*) FILTER (WHERE resolved_micros IS NULL), count(*) FILTER (WHERE resolved_micros IS NOT NULL)
        FROM vuln_findings WHERE tenant = tenant_name;
    END IF;
    SELECT max_open - open_total INTO room FROM vuln_finding_rows WHERE tenant = tenant_name;
    WITH incoming AS (
        SELECT DISTINCT ON (ecosystem, package, record_id) ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority
        FROM jsonb_to_recordset(docs) AS d (
            ecosystem text, package text, record_id text, installed_version text, fixed_version text,
            cvss double precision, epss double precision, kev boolean, priority bigint
        )
        ORDER BY ecosystem, package, record_id, priority DESC, installed_version
    ),
    matched AS (
        SELECT i.*, f.resolved_micros AS was_resolved, f.last_seen_micros AS was_seen,
            (f.installed_version, f.fixed_version, f.cvss, f.epss, f.kev, f.priority)
                IS DISTINCT FROM (i.installed_version, i.fixed_version, i.cvss, i.epss, i.kev, i.priority) AS changed
        FROM incoming i JOIN vuln_findings f
            ON f.tenant = tenant_name AND f.asset = asset_name AND f.ecosystem = i.ecosystem AND f.package = i.package AND f.record_id = i.record_id
    ),
    fresh AS (
        SELECT i.* FROM incoming i
        WHERE NOT EXISTS (
            SELECT 1 FROM vuln_findings f
            WHERE f.tenant = tenant_name AND f.asset = asset_name AND f.ecosystem = i.ecosystem AND f.package = i.package AND f.record_id = i.record_id
        )
    ),
    resolved AS (
        UPDATE vuln_findings f SET resolved_micros = now_micros
        WHERE f.tenant = tenant_name AND f.asset = asset_name AND f.resolved_micros IS NULL
            AND NOT EXISTS (SELECT 1 FROM incoming i WHERE i.ecosystem = f.ecosystem AND i.package = f.package AND i.record_id = f.record_id)
        RETURNING 1
    ),
    candidates AS (
        SELECT ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, true AS is_new FROM fresh
        UNION ALL
        SELECT ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, false FROM matched WHERE was_resolved IS NOT NULL
    ),
    admitted AS (
        SELECT * FROM candidates ORDER BY priority DESC, ecosystem, package, record_id LIMIT greatest(room + (SELECT count(*) FROM resolved), 0)
    ),
    stored AS (
        INSERT INTO vuln_findings (tenant, asset, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority,
            first_seen_micros, last_seen_micros, resolved_micros)
        SELECT tenant_name, asset_name, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority,
            now_micros, now_micros, NULL FROM admitted WHERE is_new
        RETURNING 1
    ),
    refreshed AS (
        UPDATE vuln_findings f SET installed_version = m.installed_version, fixed_version = m.fixed_version, cvss = m.cvss, epss = m.epss,
            kev = m.kev, priority = m.priority, last_seen_micros = now_micros, resolved_micros = NULL
        FROM matched m
        WHERE f.tenant = tenant_name AND f.asset = asset_name AND f.ecosystem = m.ecosystem AND f.package = m.package AND f.record_id = m.record_id
            AND ((m.was_resolved IS NULL AND (m.changed OR m.was_seen <= now_micros - granularity))
                OR EXISTS (SELECT 1 FROM admitted a WHERE NOT a.is_new AND a.ecosystem = m.ecosystem AND a.package = m.package AND a.record_id = m.record_id))
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM stored), (SELECT count(*) FROM refreshed), (SELECT count(*) FROM resolved),
        (SELECT count(*) FROM candidates) - (SELECT count(*) FROM admitted), (SELECT count(*) FROM admitted WHERE NOT is_new)
    INTO n_inserted, n_updated, n_resolved, n_refused_no_room, n_reopened;
    UPDATE vuln_finding_rows SET open_total = open_total + n_inserted + n_reopened - n_resolved, resolved_total = resolved_total + n_resolved - n_reopened
    WHERE tenant = tenant_name RETURNING resolved_total INTO resolved_now;
    n_evicted := 0;
    excess := resolved_now - max_resolved;
    IF excess > 0 THEN
        DELETE FROM vuln_findings WHERE ctid = ANY (ARRAY(
            SELECT ctid FROM vuln_findings WHERE tenant = tenant_name AND resolved_micros IS NOT NULL
            ORDER BY resolved_micros, asset, ecosystem, package, record_id LIMIT excess
        ));
        GET DIAGNOSTICS n_evicted = ROW_COUNT;
        UPDATE vuln_finding_rows SET resolved_total = resolved_total - n_evicted WHERE tenant = tenant_name;
    END IF;
END
$$;
