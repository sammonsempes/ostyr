DELETE FROM cmdb_events
WHERE (tenant, id) IN (
    SELECT tenant, id FROM (
        SELECT tenant, id,
            row_number() OVER (PARTITION BY tenant, asset, kind, lifecycle ORDER BY id) AS position
        FROM cmdb_events
    ) ranked
    WHERE position > 1
);

ALTER TABLE cmdb_events
    ADD CONSTRAINT cmdb_events_once UNIQUE NULLS NOT DISTINCT (tenant, asset, kind, lifecycle);
