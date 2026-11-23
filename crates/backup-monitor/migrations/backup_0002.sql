CREATE OR REPLACE FUNCTION backup_restore_record(p_tenant text, p_results jsonb, p_declared jsonb, p_cap bigint, p_max_skew_seconds bigint)
RETURNS TABLE (outcome text, written bigint, stale_write bigint, config_changed bigint, pruned bigint, row_count bigint)
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $body$
DECLARE
    now_micros bigint;
    cap bigint := least(greatest(p_cap, 0), 10000);
    skew bigint := least(greatest(p_max_skew_seconds, 0), 300);
    total bigint;
    done_written bigint;
    done_stale bigint;
    done_changed bigint;
    done_pruned bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('backup_restore/' || p_tenant, 0::bigint));
    now_micros := (extract(epoch from clock_timestamp()) * 1000000)::bigint;
    IF EXISTS (
        SELECT 1 FROM jsonb_to_recordset(p_results) AS r(tested_micros bigint, db_clock boolean, outcome text)
        WHERE (r.tested_micros IS NULL AND r.db_clock IS NOT TRUE) OR (r.db_clock IS TRUE AND r.outcome IS DISTINCT FROM 'run_error')
    ) THEN
        RETURN QUERY SELECT 'bad_time'::text, 0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint;
        RETURN;
    END IF;
    IF EXISTS (
        SELECT 1 FROM jsonb_to_recordset(p_results) AS r(tested_micros bigint)
        WHERE r.tested_micros > now_micros + skew * 1000000
    ) THEN
        RETURN QUERY SELECT 'clock_skew'::text, 0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint;
        RETURN;
    END IF;
    SELECT count(*) INTO total FROM (
        SELECT d.repository, d.host, d.path FROM jsonb_to_recordset(p_declared) AS d(repository text, host text, path text)
        WHERE EXISTS (
            SELECT 1 FROM backup_restore_tests t
            WHERE t.tenant = p_tenant AND t.repository = d.repository AND t.host = d.host AND t.path = d.path
        ) OR EXISTS (
            SELECT 1 FROM jsonb_to_recordset(p_results) AS r(repository text, host text, path text)
            WHERE r.repository = d.repository AND r.host = d.host AND r.path = d.path
        )
    ) AS kept;
    IF total > cap THEN
        RETURN QUERY SELECT 'row_cap'::text, 0::bigint, 0::bigint, 0::bigint, 0::bigint, total;
        RETURN;
    END IF;
    WITH input AS (
        SELECT DISTINCT ON (r.repository, r.host, r.path) r.*
        FROM (
            SELECT e.repository, e.host, e.path, e.config_id, e.snapshot_id, e.snapshot_micros, e.outcome, e.category,
                CASE WHEN e.db_clock IS TRUE THEN now_micros ELSE e.tested_micros END AS tested_micros
            FROM jsonb_to_recordset(p_results) AS e(
                repository text, host text, path text, config_id text, snapshot_id text, snapshot_micros bigint, tested_micros bigint, outcome text,
                category text, db_clock boolean
            )
        ) AS r
        ORDER BY r.repository, r.host, r.path, r.tested_micros DESC, (r.outcome = 'restored') ASC, (r.outcome = 'run_error') DESC
    ), joined AS (
        SELECT i.*, s.tested_micros AS old_tested, s.restored_config_id AS old_restored
        FROM input i
        LEFT JOIN backup_restore_tests s
            ON s.tenant = p_tenant AND s.repository = i.repository AND s.host = i.host AND s.path = i.path
    ), written AS (
        INSERT INTO backup_restore_tests AS st (
            tenant, repository, host, path, config_id, snapshot_id, snapshot_micros, tested_micros, outcome, category,
            restored_config_id, restored_snapshot_micros, restored_tested_micros
        )
        SELECT p_tenant, j.repository, j.host, j.path, j.config_id, j.snapshot_id, j.snapshot_micros, j.tested_micros, j.outcome, j.category,
            CASE WHEN j.outcome = 'restored' THEN j.config_id END,
            CASE WHEN j.outcome = 'restored' THEN j.snapshot_micros END,
            CASE WHEN j.outcome = 'restored' THEN j.tested_micros END
        FROM joined j WHERE j.old_tested IS NULL OR j.old_tested < j.tested_micros
        ON CONFLICT (tenant, repository, host, path) DO UPDATE SET
            config_id = EXCLUDED.config_id,
            snapshot_id = EXCLUDED.snapshot_id,
            snapshot_micros = EXCLUDED.snapshot_micros,
            tested_micros = EXCLUDED.tested_micros,
            outcome = EXCLUDED.outcome,
            category = EXCLUDED.category,
            restored_config_id = CASE
                WHEN EXCLUDED.outcome = 'restored' THEN EXCLUDED.config_id
                WHEN EXCLUDED.outcome = 'run_error' THEN st.restored_config_id
                WHEN st.restored_config_id IS DISTINCT FROM EXCLUDED.config_id THEN NULL
                ELSE st.restored_config_id
            END,
            restored_snapshot_micros = CASE
                WHEN EXCLUDED.outcome = 'restored' THEN EXCLUDED.snapshot_micros
                WHEN EXCLUDED.outcome = 'run_error' THEN st.restored_snapshot_micros
                WHEN st.restored_config_id IS DISTINCT FROM EXCLUDED.config_id THEN NULL
                ELSE st.restored_snapshot_micros
            END,
            restored_tested_micros = CASE
                WHEN EXCLUDED.outcome = 'restored' THEN EXCLUDED.tested_micros
                WHEN EXCLUDED.outcome = 'run_error' THEN st.restored_tested_micros
                WHEN st.restored_config_id IS DISTINCT FROM EXCLUDED.config_id THEN NULL
                ELSE st.restored_tested_micros
            END
        WHERE st.tested_micros < EXCLUDED.tested_micros
        RETURNING st.repository, st.host, st.path
    )
    SELECT
        (SELECT count(*) FROM written),
        (SELECT count(*) FROM joined WHERE old_tested IS NOT NULL AND NOT old_tested < tested_micros),
        (SELECT count(*) FROM joined WHERE old_restored IS NOT NULL AND old_restored <> config_id AND old_tested < tested_micros)
    INTO done_written, done_stale, done_changed;
    DELETE FROM backup_restore_tests t
    WHERE t.tenant = p_tenant AND NOT EXISTS (
        SELECT 1 FROM jsonb_to_recordset(p_declared) AS d(repository text, host text, path text)
        WHERE d.repository = t.repository AND d.host = t.host AND d.path = t.path
    );
    GET DIAGNOSTICS done_pruned = ROW_COUNT;
    RETURN QUERY SELECT 'ok'::text, done_written, done_stale, done_changed, done_pruned, total;
END
$body$;
