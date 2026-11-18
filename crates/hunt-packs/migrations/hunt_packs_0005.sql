CREATE INDEX hunt_pack_findings_listable ON hunt_pack_findings (tenant, window_end, pack_id) WHERE octet_length(pack_id) <= 64;
