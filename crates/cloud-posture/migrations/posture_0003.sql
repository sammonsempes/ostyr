ALTER TABLE cloud_posture_findings ADD COLUMN page_key bytea GENERATED ALWAYS AS (int4send(32767 - severity_rank::integer) || identity) STORED;
CREATE INDEX cloud_posture_findings_page_key ON cloud_posture_findings (tenant, account, page_key);
DROP INDEX cloud_posture_findings_page;
CREATE FUNCTION posture_page(tenant_name text, account_name text, rank_value integer, identity_hex text, row_limit bigint)
RETURNS SETOF cloud_posture_findings
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET enable_sort = off SET jit = off AS $$
    SELECT f.* FROM cloud_posture_findings f
    WHERE f.tenant = tenant_name AND f.account = account_name AND f.page_key > (int4send(32767 - rank_value) || decode(identity_hex, 'hex'))
    ORDER BY f.page_key LIMIT row_limit
$$;
CREATE OR REPLACE FUNCTION posture_replace_run(
    tenant_name text, account_name text, run text, docs jsonb, finished bigint, stats jsonb, max_total bigint,
    OUT outcome text, OUT others bigint, OUT stored bigint
)
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET jit = off AS $$
DECLARE
    incoming bigint;
    other_findings bigint;
    other_runs bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('cloud_posture/' || tenant_name, 0::bigint));
    incoming := jsonb_array_length(docs);
    SELECT count(*) INTO other_findings FROM cloud_posture_findings f WHERE f.tenant = tenant_name AND f.account <> account_name;
    SELECT count(*) INTO other_runs FROM cloud_posture_runs r WHERE r.tenant = tenant_name AND r.account <> account_name;
    others := other_findings + other_runs;
    stored := 0;
    IF others + incoming + 1 > max_total THEN
        outcome := 'refused_cap';
        UPDATE cloud_posture_runs r SET refused_items = CASE WHEN r.refused_micros IS NULL OR finished > r.refused_micros THEN incoming ELSE r.refused_items END,
            refused_micros = greatest(r.refused_micros, finished) WHERE r.tenant = tenant_name AND r.account = account_name;
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
            refused_fail = EXCLUDED.refused_fail, store_refused = EXCLUDED.store_refused,
            refused_items = CASE WHEN cloud_posture_runs.refused_micros > EXCLUDED.finished_micros THEN cloud_posture_runs.refused_items ELSE 0 END,
            refused_micros = CASE WHEN cloud_posture_runs.refused_micros > EXCLUDED.finished_micros THEN cloud_posture_runs.refused_micros ELSE NULL END;
    END IF;
END
$$;
CREATE OR REPLACE FUNCTION posture_refuse_run(tenant_name text, account_name text, finished bigint, claimed bigint, max_total bigint, OUT others bigint)
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET jit = off AS $$
DECLARE
    other_findings bigint;
    other_runs bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('cloud_posture/' || tenant_name, 0::bigint));
    SELECT count(*) INTO other_findings FROM cloud_posture_findings f WHERE f.tenant = tenant_name AND f.account <> account_name;
    SELECT count(*) INTO other_runs FROM cloud_posture_runs r WHERE r.tenant = tenant_name AND r.account <> account_name;
    others := other_findings + other_runs;
    UPDATE cloud_posture_runs r SET refused_items = CASE WHEN r.refused_micros IS NULL OR finished > r.refused_micros THEN claimed ELSE r.refused_items END,
        refused_micros = greatest(r.refused_micros, finished) WHERE r.tenant = tenant_name AND r.account = account_name;
    IF NOT FOUND AND others + 1 <= max_total THEN
        INSERT INTO cloud_posture_runs (tenant, account, refused_micros, refused_items) VALUES (tenant_name, account_name, finished, claimed);
    END IF;
END
$$;
