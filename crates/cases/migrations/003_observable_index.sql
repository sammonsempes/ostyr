CREATE INDEX cases_by_observable ON cases USING gin (observables jsonb_path_ops);
