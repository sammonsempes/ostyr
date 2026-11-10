UPDATE cases SET status = change.status, resolution = change.resolution, updated_at = change.updated_at,
    history = cases.history || jsonb_build_array(change.event), version = cases.version + 1
FROM jsonb_to_record($3::text::jsonb) AS change(status text, resolution text, updated_at bigint, event jsonb, version bigint, prior_status text)
WHERE cases.tenant = $1 AND cases.id = $2::text AND cases.version = change.version
    AND cases.status = change.prior_status
    AND jsonb_array_length(cases.history) < $4::text::bigint
RETURNING cases.version::text
