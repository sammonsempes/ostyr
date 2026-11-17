ALTER TABLE hunt_pack_findings ADD CONSTRAINT hunt_pack_findings_pack_id_len CHECK (octet_length(pack_id) BETWEEN 1 AND 64) NOT VALID;
