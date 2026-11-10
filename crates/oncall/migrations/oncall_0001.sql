CREATE TABLE oncall_alerts (
    tenant text NOT NULL,
    id bigint GENERATED ALWAYS AS IDENTITY,
    fingerprint text NOT NULL,
    state text NOT NULL CHECK (state IN ('open', 'acknowledged', 'escalated', 'resolved')),
    level bigint NOT NULL DEFAULT 0,
    occurrences bigint NOT NULL DEFAULT 1,
    version bigint NOT NULL DEFAULT 0,
    opened_at timestamptz NOT NULL,
    acknowledged_at timestamptz,
    resolved_at timestamptz,
    PRIMARY KEY (tenant, id)
);
CREATE UNIQUE INDEX oncall_alerts_live_fingerprint ON oncall_alerts (tenant, fingerprint) WHERE state <> 'resolved';
CREATE TABLE oncall_notifications (
    tenant text NOT NULL,
    seq bigint GENERATED ALWAYS AS IDENTITY,
    alert bigint NOT NULL,
    channel text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('sent', 'failed')),
    reason text,
    at timestamptz NOT NULL,
    PRIMARY KEY (tenant, seq),
    FOREIGN KEY (tenant, alert) REFERENCES oncall_alerts (tenant, id)
);
