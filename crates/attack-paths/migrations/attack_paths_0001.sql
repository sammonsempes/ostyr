CREATE TABLE attack_path_report (
    tenant text NOT NULL,
    id bigserial NOT NULL,
    graph_digest text NOT NULL CHECK (graph_digest ~ '^[0-9a-f]{64}$'),
    generated timestamptz NOT NULL CHECK (generated BETWEEN '0001-01-01 00:00:00+00' AND '9999-12-31 23:59:59+00'),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    body text NOT NULL CHECK (octet_length(body) <= 1048576),
    truncated boolean NOT NULL,
    budget_reached boolean NOT NULL,
    unsearched_count bigint NOT NULL CHECK (unsearched_count >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, graph_digest, digest)
);

CREATE FUNCTION attack_path_report_store(
    p_tenant text, p_graph_digest text, p_generated text, p_digest text, p_body text,
    p_truncated boolean, p_budget_reached boolean, p_unsearched bigint, p_cap bigint)
RETURNS TABLE (outcome text, report_id text)
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $body$
DECLARE
    existing bigint;
    stored bigint;
    held bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('attack_paths/' || p_tenant, 0));
    SELECT r.id INTO existing FROM attack_path_report r
    WHERE r.tenant = p_tenant AND r.graph_digest = p_graph_digest AND r.digest = p_digest;
    IF FOUND THEN
        RETURN QUERY SELECT 'already_stored'::text, existing::text;
        RETURN;
    END IF;
    SELECT count(*) INTO held FROM attack_path_report r WHERE r.tenant = p_tenant;
    IF held >= p_cap THEN
        RETURN QUERY SELECT 'refused'::text, ''::text;
        RETURN;
    END IF;
    INSERT INTO attack_path_report (tenant, graph_digest, generated, digest, body, truncated, budget_reached, unsearched_count)
    VALUES (p_tenant, p_graph_digest, p_generated::timestamptz, p_digest, p_body, p_truncated, p_budget_reached, p_unsearched)
    RETURNING id INTO stored;
    RETURN QUERY SELECT 'stored'::text, stored::text;
END
$body$;
