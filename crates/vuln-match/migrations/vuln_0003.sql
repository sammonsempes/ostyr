LOCK TABLE vuln_findings, vuln_finding_rows, vuln_asset_resolved IN ACCESS EXCLUSIVE MODE;
CREATE TEMPORARY TABLE vuln_touched ON COMMIT DROP AS
WITH gone AS (
    DELETE FROM vuln_findings
    WHERE NOT (
            (asset ~ '^[!-~]{1,128}$' AND left(asset, 1) <> '-' AND octet_length(asset) = char_length(asset))
            AND (ecosystem ~ '^[!-~]{1,128}$' AND left(ecosystem, 1) <> '-' AND octet_length(ecosystem) = char_length(ecosystem))
            AND (package ~ '^[!-~]{1,128}$' AND left(package, 1) <> '-' AND octet_length(package) = char_length(package))
            AND (record_id ~ '^[!-~]{1,128}$' AND left(record_id, 1) <> '-' AND octet_length(record_id) = char_length(record_id))
            AND (installed_version ~ '^[!-~]{1,128}$' AND left(installed_version, 1) <> '-' AND octet_length(installed_version) = char_length(installed_version))
        )
        OR (fixed_version IS NOT NULL AND NOT (fixed_version ~ '^[!-~]{1,128}$' AND left(fixed_version, 1) <> '-'
            AND octet_length(fixed_version) = char_length(fixed_version)))
        OR priority > 4294967295
    RETURNING tenant
)
SELECT DISTINCT tenant FROM gone;
DELETE FROM vuln_asset_resolved a USING vuln_touched t WHERE a.tenant = t.tenant;
DELETE FROM vuln_finding_rows r USING vuln_touched t WHERE r.tenant = t.tenant;
INSERT INTO vuln_asset_resolved (tenant, asset, resolved_total, healed_day)
SELECT f.tenant, f.asset, count(*), floor(extract(epoch FROM now()) / 86400)::bigint
FROM vuln_findings f JOIN vuln_touched t ON t.tenant = f.tenant
WHERE f.resolved_micros IS NOT NULL GROUP BY f.tenant, f.asset;
INSERT INTO vuln_finding_rows (tenant, open_total, resolved_total)
SELECT t.tenant, count(f.tenant) FILTER (WHERE f.resolved_micros IS NULL), count(f.tenant) FILTER (WHERE f.resolved_micros IS NOT NULL)
FROM vuln_touched t LEFT JOIN vuln_findings f ON f.tenant = t.tenant GROUP BY t.tenant;
ALTER TABLE vuln_findings
    ADD CONSTRAINT vuln_findings_asset_grammar CHECK (asset ~ '^[!-~]{1,128}$' AND left(asset, 1) <> '-' AND octet_length(asset) = char_length(asset)),
    ADD CONSTRAINT vuln_findings_ecosystem_grammar
        CHECK (ecosystem ~ '^[!-~]{1,128}$' AND left(ecosystem, 1) <> '-' AND octet_length(ecosystem) = char_length(ecosystem)),
    ADD CONSTRAINT vuln_findings_package_grammar
        CHECK (package ~ '^[!-~]{1,128}$' AND left(package, 1) <> '-' AND octet_length(package) = char_length(package)),
    ADD CONSTRAINT vuln_findings_record_id_grammar
        CHECK (record_id ~ '^[!-~]{1,128}$' AND left(record_id, 1) <> '-' AND octet_length(record_id) = char_length(record_id)),
    ADD CONSTRAINT vuln_findings_installed_version_grammar CHECK (
        installed_version ~ '^[!-~]{1,128}$' AND left(installed_version, 1) <> '-' AND octet_length(installed_version) = char_length(installed_version)
    ),
    ADD CONSTRAINT vuln_findings_fixed_version_grammar CHECK (
        fixed_version IS NULL
        OR (fixed_version ~ '^[!-~]{1,128}$' AND left(fixed_version, 1) <> '-' AND octet_length(fixed_version) = char_length(fixed_version))
    ),
    ADD CONSTRAINT vuln_findings_priority_range CHECK (priority <= 4294967295);
CREATE INDEX vuln_findings_open_asset_rank ON vuln_findings (tenant, asset, priority DESC, ecosystem, package, record_id) WHERE resolved_micros IS NULL;
