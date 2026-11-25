CREATE TABLE playbook_runs (
    tenant text NOT NULL,
    id text NOT NULL,
    run_seq bigint GENERATED ALWAYS AS IDENTITY,
    created bigint NOT NULL CHECK (created >= 0),
    alert_id text NOT NULL,
    playbook text NOT NULL,
    mode text NOT NULL CHECK (mode = 'dry_run'),
    outcome text NOT NULL CHECK (outcome IN ('completed', 'halted', 'needs_approval')),
    steps bigint NOT NULL CHECK (steps >= 0),
    trace jsonb NOT NULL,
    PRIMARY KEY (tenant, id)
);
CREATE INDEX playbook_runs_by_seq ON playbook_runs (tenant, run_seq);
