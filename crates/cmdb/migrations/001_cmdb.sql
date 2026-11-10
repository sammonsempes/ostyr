CREATE TABLE cmdb_assets (
    tenant text NOT NULL,
    id text NOT NULL,
    kind text NOT NULL,
    lifecycle text NOT NULL,
    version bigint NOT NULL,
    PRIMARY KEY (tenant, id)
);

CREATE TABLE cmdb_identity_keys (
    tenant text NOT NULL,
    key text NOT NULL,
    value text NOT NULL,
    asset text NOT NULL,
    PRIMARY KEY (tenant, key, value),
    FOREIGN KEY (tenant, asset) REFERENCES cmdb_assets (tenant, id)
);

CREATE TABLE cmdb_attributes (
    tenant text NOT NULL,
    asset text NOT NULL,
    name text NOT NULL,
    value text NOT NULL,
    source text NOT NULL,
    PRIMARY KEY (tenant, asset, name),
    FOREIGN KEY (tenant, asset) REFERENCES cmdb_assets (tenant, id)
);

CREATE TABLE cmdb_conflicts (
    tenant text NOT NULL,
    id bigint GENERATED ALWAYS AS IDENTITY,
    asset text NOT NULL,
    attribute text NOT NULL,
    current_value text NOT NULL,
    current_source text NOT NULL,
    observed_value text NOT NULL,
    observed_source text NOT NULL,
    resolution text NOT NULL,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, asset) REFERENCES cmdb_assets (tenant, id)
);

CREATE TABLE cmdb_events (
    tenant text NOT NULL,
    id bigint GENERATED ALWAYS AS IDENTITY,
    asset text NOT NULL,
    kind text NOT NULL,
    lifecycle text,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, asset) REFERENCES cmdb_assets (tenant, id)
);
