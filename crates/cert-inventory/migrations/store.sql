WITH room AS (
    SELECT n_certs, n_sightings FROM cert_inventory_room($1)
), incoming AS (
    SELECT doc.fingerprint, doc.subject, doc.issuer, doc.dns_names, doc.not_before, doc.not_after, doc.key_type, doc.key_bits, doc.self_signed
    FROM jsonb_to_recordset($2::text::jsonb) AS doc(
        fingerprint text, subject text, issuer text, dns_names jsonb, not_before bigint, not_after bigint,
        key_type text, key_bits bigint, self_signed boolean
    )
    WHERE (SELECT n_certs FROM room) IS NOT NULL
), flagged AS (
    SELECT i.*,
        EXISTS (SELECT 1 FROM cert_inventory c WHERE c.tenant = $1 AND c.fingerprint = i.fingerprint) AS known,
        EXISTS (
            SELECT 1 FROM cert_sightings s
            WHERE s.tenant = $1 AND s.fingerprint = i.fingerprint AND s.source_kind = $3::text AND s.source_ref = $4::text
        ) AS sighted
    FROM incoming i
), cert_ranked AS (
    SELECT f.*, (f.known OR row_number() OVER (PARTITION BY f.known ORDER BY f.fingerprint)
        <= greatest($6::text::bigint - (SELECT n_certs FROM room), 0)) AS cert_ok
    FROM flagged f
), sighting_ranked AS (
    SELECT c.*, (c.sighted OR row_number() OVER (PARTITION BY (c.cert_ok AND NOT c.sighted) ORDER BY c.fingerprint)
        <= greatest($7::text::bigint - (SELECT n_sightings FROM room), 0)) AS sighting_ok
    FROM cert_ranked c
), accepted AS (
    SELECT * FROM sighting_ranked WHERE cert_ok AND sighting_ok
), written AS (
    INSERT INTO cert_inventory (
        tenant, fingerprint, subject, issuer, dns_names, not_before, not_after, key_type, key_bits, self_signed, first_seen, last_seen
    )
    SELECT $1::text, a.fingerprint, a.subject, a.issuer, ARRAY(SELECT jsonb_array_elements_text(a.dns_names)), a.not_before, a.not_after,
        a.key_type, a.key_bits, a.self_signed, $5::text::bigint, $5::text::bigint
    FROM accepted a
    ON CONFLICT (tenant, fingerprint) DO UPDATE SET last_seen = greatest(cert_inventory.last_seen, EXCLUDED.last_seen)
    RETURNING (xmax = 0) AS inserted
), sightings AS (
    INSERT INTO cert_sightings (tenant, fingerprint, source_kind, source_ref, last_seen)
    SELECT $1::text, a.fingerprint, $3::text, $4::text, $5::text::bigint FROM accepted a
    ON CONFLICT (tenant, fingerprint, source_kind, source_ref) DO UPDATE SET last_seen = greatest(cert_sightings.last_seen, EXCLUDED.last_seen)
    RETURNING 1
)
SELECT (SELECT count(*) FROM written WHERE inserted)::text,
    (SELECT count(*) FROM written WHERE NOT inserted)::text,
    ((SELECT count(*) FROM incoming) - (SELECT count(*) FROM accepted))::text
