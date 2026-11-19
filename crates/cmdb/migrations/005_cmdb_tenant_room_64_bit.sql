CREATE OR REPLACE FUNCTION cmdb_tenant_room(tenant_name text, OUT n_assets bigint, OUT n_keys bigint, OUT n_attributes bigint)
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('cmdb_tenant_room/' || tenant_name, 0));
    SELECT count(*) INTO n_assets FROM cmdb_assets WHERE tenant = tenant_name;
    SELECT count(*) INTO n_keys FROM cmdb_identity_keys WHERE tenant = tenant_name;
    SELECT count(*) INTO n_attributes FROM cmdb_attributes WHERE tenant = tenant_name;
END
$$;
