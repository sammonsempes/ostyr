CREATE INDEX cmdb_assets_id_c ON cmdb_assets (tenant, id COLLATE "C");

CREATE INDEX cmdb_identity_keys_asset ON cmdb_identity_keys (tenant, asset);
