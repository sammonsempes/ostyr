UPDATE cases SET status = change.status, resolution = change.resolution, updated_at = change.updated_at,
    history = cases.history || jsonb_build_array(change.event), version = cases.version + 1
FROM jsonb_to_record($3::text::jsonb) AS change(status text, resolution text, updated_at bigint, event jsonb, version bigint)
WHERE cases.tenant = $1 AND cases.id = $2::text AND cases.version = change.version
RETURNING cases.version::text
