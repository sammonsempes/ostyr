WITH target AS (
    SELECT jsonb_array_length(comments) AS size FROM cases WHERE tenant = $1 AND id = $2::text
), added AS (
    UPDATE cases SET comments = comments || jsonb_build_array($3::text::jsonb)
    WHERE tenant = $1 AND id = $2::text AND jsonb_array_length(comments) < $4::text::int
    RETURNING 1
)
SELECT (SELECT count(*) FROM target)::text, (SELECT count(*) FROM added)::text, COALESCE((SELECT size FROM target), 0)::text
