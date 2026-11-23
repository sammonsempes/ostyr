CREATE TABLE grc_report (
    tenant text NOT NULL,
    id bigserial NOT NULL,
    framework text NOT NULL CHECK (octet_length(framework) BETWEEN 1 AND 256),
    framework_version bigint NOT NULL,
    generated date NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    body text NOT NULL CHECK (octet_length(body) <= 1048576),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, framework, generated, digest)
);

CREATE FUNCTION grc_report_store(p_tenant text, p_framework text, p_version bigint, p_generated text, p_digest text, p_body text, p_cap bigint)
RETURNS TABLE (outcome text, report_id text)
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $body$
DECLARE
    existing bigint;
    stored bigint;
    held bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('grc_report/' || p_tenant, 0));
    SELECT r.id INTO existing FROM grc_report r
    WHERE r.tenant = p_tenant AND r.framework = p_framework AND r.generated = p_generated::date AND r.digest = p_digest;
    IF FOUND THEN
        RETURN QUERY SELECT 'already_stored'::text, existing::text;
        RETURN;
    END IF;
    SELECT count(*) INTO held FROM grc_report r WHERE r.tenant = p_tenant;
    IF held >= p_cap THEN
        RETURN QUERY SELECT 'refused'::text, ''::text;
        RETURN;
    END IF;
    INSERT INTO grc_report (tenant, framework, framework_version, generated, digest, body)
    VALUES (p_tenant, p_framework, p_version, p_generated::date, p_digest, p_body)
    RETURNING id INTO stored;
    RETURN QUERY SELECT 'stored'::text, stored::text;
END
$body$;
