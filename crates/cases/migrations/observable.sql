WITH target AS (
    SELECT jsonb_array_length(observables) AS size FROM cases WHERE tenant = $1 AND id = $2::text
), added AS (
    UPDATE cases SET observables = observables || jsonb_build_array($3::text::jsonb)
    WHERE tenant = $1 AND id = $2::text AND jsonb_array_length(observables) < $4::text::int
    AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(cases.observables) AS seen
        WHERE seen->>'kind' = ($3::text::jsonb)->>'kind' AND seen->>'value' = ($3::text::jsonb)->>'value'
    )
    RETURNING 1
)
SELECT (SELECT count(*) FROM target)::text, (SELECT count(*) FROM added)::text, COALESCE((SELECT size FROM target), 0)::text
