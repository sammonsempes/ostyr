WITH target AS (
    SELECT jsonb_array_length(observables) AS size,
    EXISTS (
        SELECT 1 FROM jsonb_array_elements(cases.observables) AS held
        WHERE held->>'kind' = ($3::text::jsonb)->>'kind' AND held->>'value' = ($3::text::jsonb)->>'value'
    )::int AS same
    FROM cases WHERE tenant = $1 AND id = $2::text
), added AS (
    UPDATE cases SET observables = observables || jsonb_build_array($3::text::jsonb)
    WHERE tenant = $1 AND id = $2::text AND jsonb_array_length(observables) < $4::text::int
    AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(cases.observables) AS seen
        WHERE seen->>'kind' = ($3::text::jsonb)->>'kind' AND seen->>'value' = ($3::text::jsonb)->>'value'
    )
    RETURNING 1
), indexed AS (
    INSERT INTO case_observable_index (tenant, kind, value_digest, case_id)
    SELECT $1, ($3::text::jsonb)->>'kind', sha256(convert_to(($3::text::jsonb)->>'value', 'UTF8')), $2::text FROM added
    RETURNING 1
)
SELECT (SELECT count(*) FROM target)::text, (SELECT count(*) FROM added)::text, COALESCE((SELECT size FROM target), 0)::text, COALESCE((SELECT same FROM target), 0)::text
