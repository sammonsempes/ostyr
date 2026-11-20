DELETE FROM compliance_state
WHERE baseline !~ '^[0-9A-Za-z][0-9A-Za-z._-]{0,49}$'
    OR control !~ '^[0-9A-Za-z][0-9A-Za-z._-]{0,49}$'
    OR asset !~ '^[0-9A-Za-z][0-9A-Za-z._+:@/~^-]{0,99}$'
    OR octet_length(baseline) <> char_length(baseline)
    OR octet_length(control) <> char_length(control)
    OR octet_length(asset) <> char_length(asset);

UPDATE compliance_state_count c SET rows = (SELECT count(*) FROM compliance_state s WHERE s.tenant = c.tenant);

ALTER TABLE compliance_state ADD CONSTRAINT compliance_state_keys CHECK (
    baseline ~ '^[0-9A-Za-z][0-9A-Za-z._-]{0,49}$'
    AND control ~ '^[0-9A-Za-z][0-9A-Za-z._-]{0,49}$'
    AND asset ~ '^[0-9A-Za-z][0-9A-Za-z._+:@/~^-]{0,99}$'
    AND octet_length(baseline) = char_length(baseline)
    AND octet_length(control) = char_length(control)
    AND octet_length(asset) = char_length(asset)
);

CREATE INDEX compliance_state_verdict ON compliance_state (tenant, verdict, baseline, control, asset);

CREATE INDEX compliance_state_asset ON compliance_state (tenant, asset, baseline, control);
