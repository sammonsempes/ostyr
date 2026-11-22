CREATE TABLE remote_shell_signed (
    tenant text NOT NULL,
    session_id text NOT NULL CHECK (char_length(session_id) BETWEEN 1 AND 128),
    agent_id text NOT NULL CHECK (char_length(agent_id) BETWEEN 1 AND 255),
    approvers text NOT NULL,
    max_seconds bigint NOT NULL CHECK (max_seconds BETWEEN 1 AND 43200),
    idle_seconds bigint NOT NULL CHECK (idle_seconds BETWEEN 1 AND 3600),
    issued_at bigint NOT NULL,
    expires_at bigint NOT NULL CHECK (expires_at >= issued_at),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    sequence bigint CHECK (sequence >= 0),
    PRIMARY KEY (tenant, session_id),
    FOREIGN KEY (tenant, session_id) REFERENCES remote_shell_sessions (tenant, session_id)
);
CREATE INDEX remote_shell_signed_pending ON remote_shell_signed (tenant, expires_at);
CREATE FUNCTION remote_shell_signed_append_once() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF OLD.sequence IS NOT NULL
        OR NEW.sequence IS NULL
        OR NEW.tenant IS DISTINCT FROM OLD.tenant
        OR NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
        OR NEW.approvers IS DISTINCT FROM OLD.approvers
        OR NEW.max_seconds IS DISTINCT FROM OLD.max_seconds
        OR NEW.idle_seconds IS DISTINCT FROM OLD.idle_seconds
        OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.key_id IS DISTINCT FROM OLD.key_id THEN
        RAISE EXCEPTION 'remote_shell_signed: a row is written once and only its sequence is filled in, once';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER remote_shell_signed_append_once BEFORE UPDATE ON remote_shell_signed
    FOR EACH ROW EXECUTE FUNCTION remote_shell_signed_append_once();
CREATE FUNCTION remote_shell_signed_no_delete() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'remote_shell_signed: a row is evidence and is never deleted or truncated';
END
$$;
CREATE TRIGGER remote_shell_signed_no_delete BEFORE DELETE ON remote_shell_signed
    FOR EACH ROW EXECUTE FUNCTION remote_shell_signed_no_delete();
CREATE TRIGGER remote_shell_signed_no_truncate BEFORE TRUNCATE ON remote_shell_signed
    FOR EACH STATEMENT EXECUTE FUNCTION remote_shell_signed_no_delete();
CREATE FUNCTION remote_shell_sign_claim(p_tenant text, p_session text, p_requester text, p_asset text, p_ticket text, p_opened_at bigint,
    p_agent text, p_approvers text, p_max bigint, p_idle bigint, p_issued bigint, p_expires bigint, p_key text, p_cap bigint)
RETURNS TABLE(out_session text) LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('remote_shell_sign/' || p_tenant, 0::bigint));
    IF (SELECT count(*) FROM remote_shell_signed g WHERE g.tenant = p_tenant AND g.expires_at >= p_issued) >= p_cap THEN
        RETURN;
    END IF;
    INSERT INTO remote_shell_signed (tenant, session_id, agent_id, approvers, max_seconds, idle_seconds, issued_at, expires_at, key_id)
        SELECT s.tenant, s.session_id, p_agent, p_approvers, p_max, p_idle, p_issued, p_expires, p_key
        FROM remote_shell_sessions s
        WHERE s.tenant = p_tenant AND s.session_id = p_session AND s.closed_at IS NULL AND s.requester = p_requester
            AND s.asset = p_asset AND s.ticket = p_ticket AND s.opened_at = p_opened_at
        ON CONFLICT (tenant, session_id) DO NOTHING RETURNING remote_shell_signed.session_id INTO out_session;
    IF FOUND THEN
        RETURN NEXT;
    END IF;
END
$$;
