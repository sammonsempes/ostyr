SELECT me.id, COALESCE(mine.ordinal, 0)::text, COALESCE(other.id, '')
FROM cases AS me
LEFT JOIN LATERAL jsonb_array_elements(me.observables) WITH ORDINALITY AS mine(item, ordinal) ON true
LEFT JOIN LATERAL (
    SELECT found.id FROM (
        SELECT cases.id FROM cases
        WHERE cases.tenant = $1 AND cases.id <> me.id AND mine.item IS NOT NULL
        AND cases.observables @> jsonb_build_array(jsonb_build_object('kind', mine.item->'kind', 'value', mine.item->'value'))
        OFFSET 0
    ) AS found ORDER BY found.id LIMIT $3::text::bigint
) AS other ON true
WHERE me.tenant = $1 AND me.id = $2::text
ORDER BY mine.ordinal, other.id
