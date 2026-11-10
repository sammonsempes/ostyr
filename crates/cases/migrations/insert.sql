INSERT INTO cases (
    tenant, id, title, description, severity, status, resolution, assignee, template, case_type,
    created_at, updated_at, version, tasks, observables, comments, history
)
SELECT $1::text, doc.id, doc.title, doc.description, doc.severity, doc.status, doc.resolution, doc.assignee, doc.template, doc.case_type,
    doc.created_at, doc.updated_at, 1, doc.tasks, doc.observables, doc.comments, doc.history
FROM jsonb_to_record($2::text::jsonb) AS doc(
    id text, title text, description text, severity text, status text, resolution text, assignee text, template text, case_type text,
    created_at bigint, updated_at bigint, tasks jsonb, observables jsonb, comments jsonb, history jsonb
)
ON CONFLICT (tenant, id) DO NOTHING
RETURNING id
