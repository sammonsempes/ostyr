ALTER FUNCTION vuln_incoming(jsonb) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION vuln_counters_rebuild(text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION vuln_scan_store(text, text, jsonb, bigint, bigint, bigint, bigint, bigint) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION vuln_open_first(text, bigint) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION vuln_open_next(text, bigint, text, text, text, text, bigint) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION vuln_open_of_asset(text, text, bigint) SET search_path = pg_catalog, public, pg_temp;
