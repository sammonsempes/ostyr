ALTER TABLE ai_budget_day
    ADD COLUMN held_calls bigint NOT NULL DEFAULT 0 CHECK (held_calls >= 0),
    ADD COLUMN held_tokens bigint NOT NULL DEFAULT 0 CHECK (held_tokens >= 0),
    ADD COLUMN held_at timestamptz NOT NULL DEFAULT now();
