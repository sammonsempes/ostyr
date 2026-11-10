ALTER TABLE alert_outbox ADD COLUMN queued_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX alert_outbox_by_queued ON alert_outbox (tenant, queued_at);
