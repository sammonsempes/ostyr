CREATE TABLE dhcp_lookup_cursor (
    tenant text PRIMARY KEY,
    next_chunk bigint NOT NULL CHECK (next_chunk >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
