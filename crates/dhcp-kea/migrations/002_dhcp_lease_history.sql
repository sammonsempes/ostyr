CREATE TABLE dhcp_lease_history (
    tenant text NOT NULL,
    lease_key bytea NOT NULL,
    address inet NOT NULL,
    mac text,
    hostname text,
    starts timestamptz NOT NULL,
    ends timestamptz NOT NULL,
    action text NOT NULL,
    subnet_id bigint NOT NULL,
    PRIMARY KEY (tenant, lease_key)
);
CREATE INDEX dhcp_lease_history_address ON dhcp_lease_history (tenant, address, starts DESC);
CREATE INDEX dhcp_lease_history_mac ON dhcp_lease_history (tenant, mac, starts DESC);
CREATE INDEX dhcp_lease_history_ends ON dhcp_lease_history (tenant, ends);
CREATE FUNCTION dhcp_history_store(
    tenant_name text, docs jsonb, max_rows bigint, retention_days bigint, now_seconds bigint,
    OUT n_expired bigint, OUT n_inserted bigint, OUT n_duplicate bigint, OUT n_refused_full bigint, OUT n_stale bigint
)
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    cutoff timestamptz := to_timestamp(now_seconds - retention_days * 86400);
    room bigint;
    n_fresh bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(1145586512, hashtext(tenant_name));
    DELETE FROM dhcp_lease_history WHERE tenant = tenant_name AND ends < cutoff;
    GET DIAGNOSTICS n_expired = ROW_COUNT;
    SELECT max_rows - count(*) INTO room FROM dhcp_lease_history WHERE tenant = tenant_name;
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
    admitted AS (SELECT * FROM fresh ORDER BY starts, lease_key LIMIT greatest(room, 0)),
    stored AS (
        INSERT INTO dhcp_lease_history (tenant, lease_key, address, mac, hostname, starts, ends, action, subnet_id)
        SELECT tenant_name, lease_key, address, mac, hostname, starts, ends, action, subnet_id FROM admitted
        ON CONFLICT (tenant, lease_key) DO NOTHING
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM stored), (SELECT count(*) FROM fresh), (SELECT count(*) FROM incoming) - (SELECT count(*) FROM current_rows)
    INTO n_inserted, n_fresh, n_stale;
    n_duplicate := jsonb_array_length(docs) - n_stale - n_fresh;
    n_refused_full := n_fresh - n_inserted;
END
$$;
