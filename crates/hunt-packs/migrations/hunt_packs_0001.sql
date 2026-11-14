CREATE TABLE hunt_pack_runs (
    tenant text NOT NULL,
    pack_id text NOT NULL,
    last_done_end bigint NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, pack_id)
);
