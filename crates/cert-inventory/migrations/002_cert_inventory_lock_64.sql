CREATE OR REPLACE FUNCTION cert_inventory_room(tenant_name text, OUT n_certs bigint, OUT n_sightings bigint)
LANGUAGE plpgsql VOLATILE
SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('cert_inventory_room/' || tenant_name, 0));
    SELECT count(*) INTO n_certs FROM cert_inventory WHERE tenant = tenant_name;
    SELECT count(*) INTO n_sightings FROM cert_sightings WHERE tenant = tenant_name;
END
$$;
