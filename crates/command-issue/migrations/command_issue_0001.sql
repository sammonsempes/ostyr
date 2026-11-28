CREATE TABLE agent_command_sequences (
    tenant text NOT NULL,
    agent_id text NOT NULL,
    class text NOT NULL CHECK (class IN ('routine', 'sensitive')),
    last bigint NOT NULL CHECK (last >= 0),
    confirmed bigint NOT NULL DEFAULT 0 CHECK (confirmed >= 0),
    PRIMARY KEY (tenant, agent_id, class)
);
