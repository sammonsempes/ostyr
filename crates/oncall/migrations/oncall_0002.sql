CREATE TABLE oncall_alert_cursors (
    tenant text PRIMARY KEY,
    created bigint NOT NULL CHECK (created >= 0),
    id text NOT NULL
);
CREATE TABLE oncall_alert_details (
    tenant text NOT NULL,
    alert bigint NOT NULL,
    severity text NOT NULL,
    title text NOT NULL,
    host text,
    username text,
    PRIMARY KEY (tenant, alert),
    FOREIGN KEY (tenant, alert) REFERENCES oncall_alerts (tenant, id)
);
