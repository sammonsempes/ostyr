ALTER TABLE alert_triage
    DROP CONSTRAINT alert_triage_status_check,
    ADD CONSTRAINT alert_triage_status_check CHECK (status IN ('acknowledged', 'closed', 'false_positive'));
