SELECT me.id, COALESCE(mine.ordinal, 0)::text, COALESCE(other.case_id, '')
FROM cases AS me
LEFT JOIN LATERAL jsonb_array_elements(me.observables) WITH ORDINALITY AS mine(item, ordinal) ON true
LEFT JOIN LATERAL (
    SELECT found.case_id FROM case_observable_index AS found
    WHERE found.tenant = $1 AND found.kind = mine.item->>'kind'
    AND found.value_digest = sha256(convert_to(mine.item->>'value', 'UTF8')) AND found.case_id <> me.id
    ORDER BY found.case_id LIMIT $3::text::bigint
) AS other ON true
WHERE me.tenant = $1 AND me.id = $2::text
ORDER BY mine.ordinal, other.case_id
