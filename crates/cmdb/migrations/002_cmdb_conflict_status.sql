ALTER TABLE cmdb_conflicts ADD COLUMN status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved'));

CREATE INDEX cmdb_conflicts_asset_attribute ON cmdb_conflicts (tenant, asset, attribute);
