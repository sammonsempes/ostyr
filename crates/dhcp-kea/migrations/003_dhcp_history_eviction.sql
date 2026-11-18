DROP FUNCTION dhcp_history_store(text, jsonb, bigint, bigint, bigint);
CREATE TABLE dhcp_history_rows (
    tenant text PRIMARY KEY,
    total bigint NOT NULL CHECK (total >= 0)
);
CREATE FUNCTION dhcp_history_store(
    tenant_name text, docs jsonb, max_rows bigint, retention_days bigint, now_seconds bigint,
    OUT n_expired bigint, OUT n_inserted bigint, OUT n_duplicate bigint, OUT n_refused_full bigint, OUT n_stale bigint,
    OUT n_evicted bigint, OUT n_pressure bigint
)
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    cutoff timestamptz := to_timestamp(now_seconds - retention_days * 86400);
    young_after timestamptz := to_timestamp(now_seconds - retention_days * 86400 / 2);
    room bigint;
    n_fresh bigint;
    n_admitted bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(1145586512, hashtext(tenant_name));
    INSERT INTO dhcp_history_rows (tenant, total) SELECT tenant_name, count(*) FROM dhcp_lease_history WHERE tenant = tenant_name
        ON CONFLICT (tenant) DO NOTHING;
    DELETE FROM dhcp_lease_history WHERE tenant = tenant_name AND ends < cutoff;
    GET DIAGNOSTICS n_expired = ROW_COUNT;
    UPDATE dhcp_history_rows SET total = total - n_expired WHERE tenant = tenant_name RETURNING max_rows - total INTO room;
    WITH incoming AS (
        SELECT DISTINCT ON (identity) identity, address, mac, hostname, to_timestamp(starts) AS starts, to_timestamp(ends) AS ends, action, subnet_id,
            sha256(convert_to(identity, 'UTF8')) AS lease_key
        FROM jsonb_to_recordset(docs) AS d (identity text, address inet, mac text, hostname text, starts bigint, ends bigint, action text, subnet_id bigint)
    ),
    current_rows AS (SELECT * FROM incoming WHERE ends >= cutoff),
    fresh AS (
        SELECT * FROM current_rows c
        WHERE NOT EXISTS (SELECT 1 FROM dhcp_lease_history h WHERE h.tenant = tenant_name AND h.lease_key = c.lease_key)
    ),
    admitted AS (SELECT * FROM fresh ORDER BY ends DESC, starts DESC, lease_key LIMIT max_rows),
    evicted AS (
        DELETE FROM dhcp_lease_history h USING (
            SELECT lease_key FROM dhcp_lease_history WHERE tenant = tenant_name ORDER BY ends, starts, lease_key
            LIMIT greatest((SELECT count(*) FROM admitted) - room, 0)
        ) oldest
        WHERE h.tenant = tenant_name AND h.lease_key = oldest.lease_key
        RETURNING h.ends
    ),
    stored AS (
        INSERT INTO dhcp_lease_history (tenant, lease_key, address, mac, hostname, starts, ends, action, subnet_id)
        SELECT tenant_name, lease_key, address, mac, hostname, starts, ends, action, subnet_id FROM admitted
        ON CONFLICT (tenant, lease_key) DO NOTHING
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM stored), (SELECT count(*) FROM fresh), (SELECT count(*) FROM admitted),
        (SELECT count(*) FROM incoming) - (SELECT count(*) FROM current_rows), (SELECT count(*) FROM evicted),
        (SELECT count(*) FROM evicted WHERE ends >= young_after)
    INTO n_inserted, n_fresh, n_admitted, n_stale, n_evicted, n_pressure;
    UPDATE dhcp_history_rows SET total = total + n_inserted - n_evicted WHERE tenant = tenant_name;
    n_duplicate := jsonb_array_length(docs) - n_stale - n_fresh;
    n_refused_full := n_fresh - n_admitted;
END
$$;
