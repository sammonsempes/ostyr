DO $$
BEGIN
    IF pg_catalog.current_setting('server_encoding') <> 'UTF8' THEN
        RAISE EXCEPTION 'the posture store needs a UTF8 database';
    END IF;
END
$$;
CREATE TABLE cloud_posture_findings (
    tenant text NOT NULL,
    account text NOT NULL,
    identity bytea NOT NULL,
    severity_rank smallint NOT NULL,
    uid text NOT NULL,
    check_id text NOT NULL,
    status text NOT NULL,
    severity text NOT NULL,
    provider text NOT NULL,
    region text NOT NULL,
    resource_uid text NOT NULL,
    resource_type text NOT NULL,
    time_unix bigint NOT NULL,
    title text NOT NULL,
    title_cut bigint NOT NULL,
    detail text NOT NULL,
    detail_cut bigint NOT NULL,
    run_id text NOT NULL,
    PRIMARY KEY (tenant, account, identity),
    CHECK (octet_length(identity) = 32),
    CHECK (account ~ '^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*$' AND octet_length(account) <= 256 AND octet_length(account) = char_length(account)),
    CHECK (check_id ~ '^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*$' AND octet_length(check_id) <= 128 AND octet_length(check_id) = char_length(check_id)),
    CHECK (provider ~ '^[a-z0-9_]+$' AND octet_length(provider) <= 32 AND octet_length(provider) = char_length(provider)),
    CHECK (region ~ '^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*$' AND octet_length(region) <= 128 AND octet_length(region) = char_length(region)),
    CHECK (resource_uid ~ '^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*( [A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*)*$' AND octet_length(resource_uid) <= 1024 AND octet_length(resource_uid) = char_length(resource_uid)),
    CHECK (resource_type ~ '^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*( [A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*)*$' AND octet_length(resource_type) <= 128 AND octet_length(resource_type) = char_length(resource_type)),
    CHECK (run_id ~ '^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*$' AND octet_length(run_id) <= 128 AND octet_length(run_id) = char_length(run_id)),
    CHECK (status IN ('PASS', 'FAIL', 'MANUAL', 'MUTED')),
    CHECK ((severity, severity_rank) IN (('Fatal', 7), ('Critical', 6), ('High', 5), ('Medium', 4), ('Low', 3), ('Informational', 2), ('Other', 1), ('Unknown', 0))),
    CHECK (octet_length(uid) BETWEEN 1 AND 2048),
    CHECK (octet_length(title) <= 1024),
    CHECK (octet_length(detail) <= 1024),
    CHECK (title_cut >= 0),
    CHECK (detail_cut >= 0),
    CHECK (time_unix BETWEEN -62167219200 AND 253402300799)
);
CREATE INDEX cloud_posture_findings_page ON cloud_posture_findings (tenant, account, severity_rank DESC, identity);
CREATE TABLE cloud_posture_runs (
    tenant text NOT NULL,
    account text NOT NULL,
    run_id text,
    finished_micros bigint,
    items bigint NOT NULL DEFAULT 0 CHECK (items >= 0),
    unparsable bigint NOT NULL DEFAULT 0 CHECK (unparsable >= 0),
    bad_field bigint NOT NULL DEFAULT 0 CHECK (bad_field >= 0),
    duplicate bigint NOT NULL DEFAULT 0 CHECK (duplicate >= 0),
    foreign_account bigint NOT NULL DEFAULT 0 CHECK (foreign_account >= 0),
    refused_pass bigint NOT NULL DEFAULT 0 CHECK (refused_pass >= 0),
    refused_muted bigint NOT NULL DEFAULT 0 CHECK (refused_muted >= 0),
    refused_manual bigint NOT NULL DEFAULT 0 CHECK (refused_manual >= 0),
    refused_fail bigint NOT NULL DEFAULT 0 CHECK (refused_fail >= 0),
    store_refused bigint NOT NULL DEFAULT 0 CHECK (store_refused >= 0),
    refused_micros bigint,
    refused_items bigint NOT NULL DEFAULT 0 CHECK (refused_items >= 0),
    PRIMARY KEY (tenant, account),
    CHECK (account ~ '^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*$' AND octet_length(account) <= 256 AND octet_length(account) = char_length(account)),
    CHECK (run_id IS NULL OR (run_id ~ '^[A-Za-z0-9_.:/@=+,*()$#][A-Za-z0-9_.:/@=+,*()$#-]*$' AND octet_length(run_id) <= 128))
);
CREATE FUNCTION posture_replace_run(
    tenant_name text, account_name text, run text, docs jsonb, finished bigint, stats jsonb, max_total bigint,
    OUT outcome text, OUT others bigint, OUT stored bigint
)
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET jit = off AS $$
DECLARE
    incoming bigint;
    other_findings bigint;
    other_runs bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('cloud_posture/' || tenant_name, 0));
    incoming := jsonb_array_length(docs);
    SELECT count(*) INTO other_findings FROM cloud_posture_findings f WHERE f.tenant = tenant_name AND f.account <> account_name;
    SELECT count(*) INTO other_runs FROM cloud_posture_runs r WHERE r.tenant = tenant_name AND r.account <> account_name;
    others := other_findings + other_runs;
    stored := 0;
    IF others + incoming + 1 > max_total THEN
        outcome := 'refused_cap';
        UPDATE cloud_posture_runs r SET refused_micros = finished, refused_items = incoming WHERE r.tenant = tenant_name AND r.account = account_name;
        IF NOT FOUND AND others + 1 <= max_total THEN
            INSERT INTO cloud_posture_runs (tenant, account, refused_micros, refused_items) VALUES (tenant_name, account_name, finished, incoming);
        END IF;
    ELSE
        outcome := 'stored';
        DELETE FROM cloud_posture_findings f WHERE f.tenant = tenant_name AND f.account = account_name;
        INSERT INTO cloud_posture_findings (tenant, account, identity, severity_rank, uid, check_id, status, severity, provider, region, resource_uid,
            resource_type, time_unix, title, title_cut, detail, detail_cut, run_id)
        SELECT tenant_name, account_name, decode(d.identity, 'hex'), d.severity_rank, d.uid, d.check_id, d.status, d.severity, d.provider, d.region,
            d.resource_uid, d.resource_type, d.time_unix, d.title, d.title_cut, d.detail, d.detail_cut, run
        FROM jsonb_to_recordset(docs) AS d (
            identity text, severity_rank smallint, uid text, check_id text, status text, severity text, provider text, region text,
            resource_uid text, resource_type text, time_unix bigint, title text, title_cut bigint, detail text, detail_cut bigint
        );
        GET DIAGNOSTICS stored = ROW_COUNT;
        INSERT INTO cloud_posture_runs (tenant, account, run_id, finished_micros, items, unparsable, bad_field, duplicate, foreign_account,
            refused_pass, refused_muted, refused_manual, refused_fail, store_refused, refused_micros, refused_items)
        VALUES (tenant_name, account_name, run, finished, stored, (stats->>'unparsable')::bigint, (stats->>'bad_field')::bigint,
            (stats->>'duplicate')::bigint, (stats->>'foreign_account')::bigint, (stats->>'refused_pass')::bigint, (stats->>'refused_muted')::bigint,
            (stats->>'refused_manual')::bigint, (stats->>'refused_fail')::bigint, (stats->>'store_refused')::bigint, NULL, 0)
        ON CONFLICT (tenant, account) DO UPDATE SET
            run_id = EXCLUDED.run_id, finished_micros = EXCLUDED.finished_micros, items = EXCLUDED.items, unparsable = EXCLUDED.unparsable,
            bad_field = EXCLUDED.bad_field, duplicate = EXCLUDED.duplicate, foreign_account = EXCLUDED.foreign_account,
            refused_pass = EXCLUDED.refused_pass, refused_muted = EXCLUDED.refused_muted, refused_manual = EXCLUDED.refused_manual,
            refused_fail = EXCLUDED.refused_fail, store_refused = EXCLUDED.store_refused, refused_micros = NULL, refused_items = 0;
    END IF;
END
$$;
