ALTER TABLE ai_budget_day
    ADD COLUMN min_reserved bigint CHECK (min_reserved IS NULL OR min_reserved >= 0);
