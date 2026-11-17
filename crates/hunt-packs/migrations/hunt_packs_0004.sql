CREATE INDEX hunt_pack_findings_oversized ON hunt_pack_findings (tenant) WHERE octet_length(pack_id) > 64;
