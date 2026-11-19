CREATE TABLE case_observable_index (
    tenant text NOT NULL,
    kind text NOT NULL,
    value_digest bytea NOT NULL,
    case_id text NOT NULL,
    PRIMARY KEY (tenant, kind, value_digest, case_id)
);
INSERT INTO case_observable_index (tenant, kind, value_digest, case_id)
SELECT held.tenant, held.item->>'kind', sha256(convert_to(held.item->>'value', 'UTF8')), held.id
FROM (SELECT cases.tenant, cases.id, element.item FROM cases CROSS JOIN LATERAL jsonb_array_elements(cases.observables) AS element(item)) AS held
ON CONFLICT DO NOTHING
