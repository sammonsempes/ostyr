ALTER TABLE cases ADD COLUMN closed_at bigint CHECK (closed_at >= 0), ADD COLUMN ever_incident boolean NOT NULL DEFAULT false;
UPDATE cases SET
    closed_at = CASE WHEN status = 'closed' THEN updated_at END,
    ever_incident = resolution IN ('true_positive', 'other')
        OR EXISTS (SELECT 1 FROM jsonb_array_elements(cases.history) AS event WHERE event->>'kind' = 'reopened')
WHERE status = 'closed'
    OR resolution IN ('true_positive', 'other')
    OR EXISTS (SELECT 1 FROM jsonb_array_elements(cases.history) AS event WHERE event->>'kind' = 'reopened');
ALTER TABLE cases ADD CONSTRAINT cases_closed_at_matches_status CHECK ((status = 'closed') = (closed_at IS NOT NULL));
CREATE INDEX cases_by_closed ON cases (tenant, closed_at) WHERE closed_at IS NOT NULL;
CREATE INDEX cases_open ON cases (tenant, created_at) WHERE status <> 'closed';
