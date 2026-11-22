WITH window_cases AS (
    SELECT status, ever_incident, created_at, closed_at FROM cases WHERE tenant = $1 AND status <> 'closed'
    UNION ALL
    SELECT status, ever_incident, created_at, closed_at FROM cases WHERE tenant = $1 AND status = 'closed'
        AND (closed_at >= $2::text::bigint - $3::text::bigint OR created_at >= $2::text::bigint - $3::text::bigint)
), counted AS (
    SELECT status = 'closed' AS is_closed,
        created_at > $2::text::bigint OR (status = 'closed' AND (closed_at > $2::text::bigint OR closed_at < created_at)) AS bad,
        created_at, closed_at
    FROM window_cases WHERE ever_incident OR status <> 'closed'
), seconds AS (
    SELECT is_closed, bad,
        CASE WHEN bad THEN GREATEST($3::text::bigint, CASE WHEN created_at <= $2::text::bigint THEN $2::text::bigint - created_at ELSE 0 END)::numeric
            WHEN is_closed THEN (closed_at - created_at)::numeric
            ELSE ($2::text::bigint - created_at)::numeric END AS span
    FROM counted
)
SELECT coalesce((SELECT (avg(span) / 3600)::text FROM seconds), ''),
    (SELECT count(*) FROM seconds WHERE NOT is_closed)::text,
    (SELECT count(*) FROM seconds WHERE is_closed)::text,
    (SELECT count(*) FROM seconds WHERE bad)::text,
    (SELECT count(*) FROM window_cases WHERE status = 'closed' AND NOT ever_incident)::text,
    EXISTS (SELECT 1 FROM cases WHERE tenant = $1)::text,
    extract(epoch from statement_timestamp())::bigint::text
