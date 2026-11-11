CREATE TABLE alert_triage (
    tenant text NOT NULL,
    alert_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('acknowledged', 'closed')),
    actor text NOT NULL,
    note text,
    updated_at bigint NOT NULL CHECK (updated_at >= 0),
    version bigint NOT NULL,
    PRIMARY KEY (tenant, alert_id),
    FOREIGN KEY (tenant, alert_id) REFERENCES alerts (tenant, id) ON DELETE CASCADE
);
