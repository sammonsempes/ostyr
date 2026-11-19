CREATE TABLE ai_budget_day (
    tenant text NOT NULL,
    day date NOT NULL,
    calls bigint NOT NULL CHECK (calls >= 0),
    tokens bigint NOT NULL CHECK (tokens >= 0),
    PRIMARY KEY (tenant, day)
);
