ALTER TABLE case_alerts ADD COLUMN linked_by text, ADD COLUMN linked_at bigint CHECK (linked_at >= 0);
