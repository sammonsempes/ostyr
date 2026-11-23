CREATE TABLE playbook_outbox (
    tenant text NOT NULL,
    id text NOT NULL,
    seq bigint GENERATED ALWAYS AS IDENTITY,
    queued_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id)
);
CREATE INDEX playbook_outbox_by_seq ON playbook_outbox (tenant, seq);

CREATE FUNCTION playbook_outbox_enqueue()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $body$
BEGIN
    INSERT INTO playbook_outbox (tenant, id) VALUES (NEW.tenant, NEW.id) ON CONFLICT DO NOTHING;
    RETURN NEW;
END
$body$;

CREATE TRIGGER alerts_playbook_outbox AFTER INSERT ON alerts
    FOR EACH ROW EXECUTE FUNCTION playbook_outbox_enqueue();
