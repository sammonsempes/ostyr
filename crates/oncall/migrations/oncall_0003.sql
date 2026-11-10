ALTER TABLE oncall_alert_details ADD COLUMN source_alert text;
UPDATE oncall_alert_details d SET source_alert = substr(a.fingerprint, 7) FROM oncall_alerts a WHERE a.tenant = d.tenant AND a.id = d.alert;
ALTER TABLE oncall_alert_details ALTER COLUMN source_alert SET NOT NULL;
ALTER TABLE oncall_alert_details ADD CONSTRAINT oncall_alert_details_source UNIQUE (tenant, source_alert);
