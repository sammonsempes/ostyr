CREATE INDEX status_incidents_open_first ON status_incidents (tenant, (resolved_at IS NULL) DESC, started_at DESC, id DESC) WHERE published;
DROP INDEX status_incidents_published;
