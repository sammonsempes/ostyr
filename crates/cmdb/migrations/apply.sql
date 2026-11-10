WITH doc AS (
    SELECT $2::text::jsonb AS body
),
changed AS (
    SELECT a->>'id' AS id, a->>'kind' AS kind, a->>'lifecycle' AS lifecycle, (a->>'version')::bigint AS version, (a->>'touch')::boolean AS touch, a
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
incoming AS (
    SELECT DISTINCT f->>'asset' AS asset, f->>'attribute' AS attribute, f->>'current_value' AS current_value,
        f->>'current_source' AS current_source, f->>'observed_value' AS observed_value, f->>'observed_source' AS observed_source,
        f->>'resolution' AS resolution, (f->>'exempt')::boolean AS exempt, (f->>'is_key')::boolean AS is_key,
        EXISTS (
            SELECT 1 FROM cmdb_conflicts o
            WHERE o.tenant = $1 AND o.asset = f->>'asset' AND o.attribute = f->>'attribute'
              AND o.current_value = f->>'current_value' AND o.current_source = f->>'current_source'
              AND o.observed_value = f->>'observed_value' AND o.observed_source = f->>'observed_source'
              AND o.status = 'open'
        ) AS known
    FROM doc, jsonb_array_elements(body->'conflicts') AS f
),
fresh AS (
    SELECT asset, attribute, current_value, current_source, observed_value, observed_source, resolution, exempt, is_key
    FROM incoming WHERE NOT known
),
duplicates AS (
    SELECT DISTINCT asset, attribute, observed_source FROM incoming WHERE known
),
ranked AS (
    SELECT f.*, (
        SELECT count(*) FROM cmdb_conflicts o
        WHERE o.tenant = $1 AND o.asset = f.asset AND o.observed_source = f.observed_source AND o.status = 'open'
          AND (left(o.attribute, 4) = 'key:') = f.is_key
    ) + f.position <= CASE WHEN f.is_key THEN $4::text::bigint ELSE $3::text::bigint END AS admit
    FROM (
        SELECT fresh.*, row_number() OVER (
            PARTITION BY asset, observed_source, is_key
            ORDER BY attribute COLLATE "C", current_value COLLATE "C",
                current_source COLLATE "C", observed_value COLLATE "C"
        ) AS position
        FROM fresh
        WHERE NOT exempt
    ) f
),
admitted AS (
    SELECT asset, attribute, current_value, current_source, observed_value, observed_source, resolution FROM fresh WHERE exempt
    UNION ALL
    SELECT asset, attribute, current_value, current_source, observed_value, observed_source, resolution FROM ranked WHERE admit
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
      AND (c.touch OR EXISTS (SELECT 1 FROM admitted WHERE admitted.asset = c.id))
    RETURNING t.id
),
written_keys AS (
    INSERT INTO cmdb_identity_keys (tenant, key, value, asset)
    SELECT $1, k->>'key', k->>'value', c.id
    FROM changed c, jsonb_array_elements(c.a->'keys') AS k
    WHERE (SELECT ok FROM guard)
      AND NOT EXISTS (
          SELECT 1 FROM cmdb_identity_keys o
          WHERE o.tenant = $1 AND o.key = k->>'key' AND o.value = k->>'value' AND o.asset = c.id
      )
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
    SELECT $1, asset, attribute, current_value, current_source, observed_value, observed_source, resolution
    FROM admitted
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
SELECT (SELECT ok FROM guard)::text, (
    SELECT coalesce(json_agg(json_build_object('asset', asset, 'attribute', attribute, 'observed_source', observed_source)), '[]'::json)
    FROM ranked WHERE NOT admit
)::text, (
    SELECT coalesce(json_agg(json_build_object('asset', asset, 'attribute', attribute, 'observed_source', observed_source)), '[]'::json)
    FROM duplicates
)::text
