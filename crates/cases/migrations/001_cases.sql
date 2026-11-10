CREATE TABLE cases (
    tenant text NOT NULL,
    id text NOT NULL,
    title text NOT NULL,
    description text,
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status text NOT NULL CHECK (status IN ('new', 'in_progress', 'closed')),
    resolution text CHECK (resolution IN ('true_positive', 'false_positive', 'benign', 'duplicate', 'other')),
    assignee text,
    template text,
    case_type text,
    created_at bigint NOT NULL CHECK (created_at >= 0),
    updated_at bigint NOT NULL CHECK (updated_at >= 0),
    version bigint NOT NULL,
    tasks jsonb NOT NULL,
    observables jsonb NOT NULL,
    comments jsonb NOT NULL,
    history jsonb NOT NULL,
    PRIMARY KEY (tenant, id)
);
CREATE INDEX cases_by_created ON cases (tenant, created_at DESC, id DESC);
CREATE TABLE case_alerts (
    tenant text NOT NULL,
    case_id text NOT NULL,
    alert_id text NOT NULL,
    PRIMARY KEY (tenant, case_id, alert_id),
    FOREIGN KEY (tenant, case_id) REFERENCES cases (tenant, id)
);
