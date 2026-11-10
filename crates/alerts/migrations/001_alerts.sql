CREATE TABLE alerts (
    tenant text NOT NULL,
    id text NOT NULL,
    rule_id text NOT NULL,
    rule_title text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
    event_time text NOT NULL,
    created bigint NOT NULL CHECK (created >= 0),
    host_name text,
    user_name text,
    event_ids jsonb NOT NULL,
    summary text NOT NULL,
    summary_truncated boolean NOT NULL,
    summary_original_bytes bigint NOT NULL,
    PRIMARY KEY (tenant, id)
);
CREATE INDEX alerts_by_created ON alerts (tenant, created DESC, id DESC);
