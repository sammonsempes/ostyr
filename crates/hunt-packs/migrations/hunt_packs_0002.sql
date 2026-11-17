CREATE TABLE hunt_pack_findings (
    tenant text NOT NULL,
    pack_id text NOT NULL,
    window_start bigint NOT NULL,
    window_end bigint NOT NULL,
    matches bigint NOT NULL,
    max_matches bigint NOT NULL,
    found_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, pack_id, window_end)
);

CREATE INDEX hunt_pack_findings_by_end ON hunt_pack_findings (tenant, window_end, pack_id);
