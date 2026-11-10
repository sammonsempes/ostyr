CREATE TABLE alert_outbox (
    tenant text NOT NULL,
    id text NOT NULL,
    seq bigint GENERATED ALWAYS AS IDENTITY,
    PRIMARY KEY (tenant, id)
);
CREATE INDEX alert_outbox_by_seq ON alert_outbox (tenant, seq);
INSERT INTO alert_outbox (tenant, id) SELECT tenant, id FROM alerts ORDER BY created, id;
