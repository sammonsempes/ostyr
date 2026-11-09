WITH doc AS (
    SELECT $2::text::jsonb AS body
),
changed AS (
    SELECT a->>'id' AS id, a->>'kind' AS kind, a->>'lifecycle' AS lifecycle, (a->>'version')::bigint AS version, a
    FROM doc, jsonb_array_elements(body->'assets') AS a
),
locked AS (
    SELECT c.id
    FROM cmdb_assets t
    JOIN changed c ON t.id = c.id AND t.version = c.version
    WHERE t.tenant = $1
    FOR UPDATE OF t
),
guard AS (
    SELECT (SELECT count(*) FROM locked) = (SELECT count(*) FROM changed WHERE version > 0) AS ok
),
inserted AS (
    INSERT INTO cmdb_assets (tenant, id, kind, lifecycle, version)
    SELECT $1, id, kind, lifecycle, 1 FROM changed WHERE version = 0 AND (SELECT ok FROM guard)
    RETURNING id
),
updated AS (
    UPDATE cmdb_assets t
    SET kind = c.kind, lifecycle = c.lifecycle, version = t.version + 1
    FROM changed c
    WHERE t.tenant = $1 AND t.id = c.id AND t.version = c.version AND c.version > 0 AND (SELECT ok FROM guard)
    RETURNING t.id
),
written_keys AS (
    INSERT INTO cmdb_identity_keys (tenant, key, value, asset)
    SELECT $1, k->>'key', k->>'value', c.id
    FROM changed c, jsonb_array_elements(c.a->'keys') AS k
    WHERE (SELECT ok FROM guard)
    ON CONFLICT (tenant, key, value) DO NOTHING
    RETURNING asset
),
written_attributes AS (
    INSERT INTO cmdb_attributes (tenant, asset, name, value, source)
    SELECT $1, c.id, n->>'name', n->>'value', n->>'source'
    FROM changed c, jsonb_array_elements(c.a->'attributes') AS n
    WHERE (SELECT ok FROM guard)
    ON CONFLICT (tenant, asset, name) DO UPDATE SET value = EXCLUDED.value, source = EXCLUDED.source
    RETURNING asset
),
written_conflicts AS (
    INSERT INTO cmdb_conflicts (tenant, asset, attribute, current_value, current_source, observed_value, observed_source, resolution)
    SELECT $1, f->>'asset', f->>'attribute', f->>'current_value', f->>'current_source', f->>'observed_value', f->>'observed_source',
        f->>'resolution'
    FROM doc, jsonb_array_elements(body->'conflicts') AS f
    WHERE (SELECT ok FROM guard)
    RETURNING asset
),
written_events AS (
    INSERT INTO cmdb_events (tenant, asset, kind, lifecycle)
    SELECT $1, e->>'asset', e->>'kind', e->>'lifecycle'
    FROM doc, jsonb_array_elements(body->'events') AS e
    WHERE (SELECT ok FROM guard)
    RETURNING asset
)
SELECT (SELECT ok FROM guard)::text
