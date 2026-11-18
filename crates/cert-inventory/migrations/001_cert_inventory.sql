CREATE TABLE cert_inventory (
    tenant text NOT NULL,
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    subject text NOT NULL,
    issuer text NOT NULL,
    dns_names text[] NOT NULL,
    not_before bigint NOT NULL,
    not_after bigint NOT NULL,
    key_type text NOT NULL CHECK (key_type IN ('rsa', 'ec', 'other')),
    key_bits bigint,
    self_signed boolean NOT NULL,
    first_seen bigint NOT NULL,
    last_seen bigint NOT NULL,
    PRIMARY KEY (tenant, fingerprint)
);
CREATE INDEX cert_inventory_by_expiry ON cert_inventory (tenant, not_after, fingerprint);
CREATE TABLE cert_sightings (
    tenant text NOT NULL,
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    source_kind text NOT NULL CHECK (source_kind IN ('scan', 'ct')),
    source_ref text NOT NULL CHECK (octet_length(source_ref) <= 512),
    last_seen bigint NOT NULL,
    PRIMARY KEY (tenant, fingerprint, source_kind, source_ref)
);
CREATE FUNCTION cert_inventory_room(tenant_name text, OUT n_certs bigint, OUT n_sightings bigint)
LANGUAGE plpgsql VOLATILE AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(1129270340, hashtext(tenant_name));
    SELECT count(*) INTO n_certs FROM cert_inventory WHERE tenant = tenant_name;
    SELECT count(*) INTO n_sightings FROM cert_sightings WHERE tenant = tenant_name;
END
$$;
