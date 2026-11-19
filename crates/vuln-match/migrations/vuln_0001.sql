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
CREATE TABLE vuln_finding_rows (
    tenant text PRIMARY KEY,
    total bigint NOT NULL CHECK (total >= 0)
);
CREATE FUNCTION vuln_scan_store(
    tenant_name text, asset_name text, docs jsonb, max_rows bigint, now_micros bigint,
    OUT n_inserted bigint, OUT n_updated bigint, OUT n_resolved bigint, OUT n_refused_no_room bigint
)
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    room bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(1447380532, hashtext(tenant_name));
    INSERT INTO vuln_finding_rows (tenant, total) SELECT tenant_name, count(*) FROM vuln_findings WHERE tenant = tenant_name
        ON CONFLICT (tenant) DO NOTHING;
    SELECT max_rows - total INTO room FROM vuln_finding_rows WHERE tenant = tenant_name;
    WITH incoming AS (
        SELECT DISTINCT ON (ecosystem, package, record_id) ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority
        FROM jsonb_to_recordset(docs) AS d (
            ecosystem text, package text, record_id text, installed_version text, fixed_version text,
            cvss double precision, epss double precision, kev boolean, priority bigint
        )
        ORDER BY ecosystem, package, record_id, priority DESC, installed_version
    ),
    updated AS (
        UPDATE vuln_findings f SET installed_version = i.installed_version, fixed_version = i.fixed_version, cvss = i.cvss, epss = i.epss,
            kev = i.kev, priority = i.priority, last_seen_micros = now_micros, resolved_micros = NULL
        FROM incoming i
        WHERE f.tenant = tenant_name AND f.asset = asset_name AND f.ecosystem = i.ecosystem AND f.package = i.package AND f.record_id = i.record_id
        RETURNING 1
    ),
    fresh AS (
        SELECT i.* FROM incoming i
        WHERE NOT EXISTS (
            SELECT 1 FROM vuln_findings f
            WHERE f.tenant = tenant_name AND f.asset = asset_name AND f.ecosystem = i.ecosystem AND f.package = i.package AND f.record_id = i.record_id
        )
    ),
    admitted AS (
        SELECT * FROM fresh ORDER BY priority DESC, ecosystem, package, record_id LIMIT greatest(room, 0)
    ),
    stored AS (
        INSERT INTO vuln_findings (tenant, asset, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority,
            first_seen_micros, last_seen_micros, resolved_micros)
        SELECT tenant_name, asset_name, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority,
            now_micros, now_micros, NULL FROM admitted
        RETURNING 1
    ),
    resolved AS (
        UPDATE vuln_findings f SET resolved_micros = now_micros
        WHERE f.tenant = tenant_name AND f.asset = asset_name AND f.resolved_micros IS NULL
            AND NOT EXISTS (SELECT 1 FROM incoming i WHERE i.ecosystem = f.ecosystem AND i.package = f.package AND i.record_id = f.record_id)
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM stored), (SELECT count(*) FROM updated), (SELECT count(*) FROM resolved),
        (SELECT count(*) FROM fresh) - (SELECT count(*) FROM admitted)
    INTO n_inserted, n_updated, n_resolved, n_refused_no_room;
    UPDATE vuln_finding_rows SET total = total + n_inserted WHERE tenant = tenant_name;
END
$$;
