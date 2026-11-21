CREATE FUNCTION posture_refuse_run(tenant_name text, account_name text, finished bigint, claimed bigint, max_total bigint, OUT others bigint)
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET jit = off AS $$
DECLARE
    other_findings bigint;
    other_runs bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('cloud_posture/' || tenant_name, 0));
    SELECT count(*) INTO other_findings FROM cloud_posture_findings f WHERE f.tenant = tenant_name AND f.account <> account_name;
    SELECT count(*) INTO other_runs FROM cloud_posture_runs r WHERE r.tenant = tenant_name AND r.account <> account_name;
    others := other_findings + other_runs;
    UPDATE cloud_posture_runs r SET refused_micros = finished, refused_items = claimed WHERE r.tenant = tenant_name AND r.account = account_name;
    IF NOT FOUND AND others + 1 <= max_total THEN
        INSERT INTO cloud_posture_runs (tenant, account, refused_micros, refused_items) VALUES (tenant_name, account_name, finished, claimed);
    END IF;
END
$$;
