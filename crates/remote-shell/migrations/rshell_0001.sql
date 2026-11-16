CREATE TABLE remote_shell_sessions (
    tenant text NOT NULL,
    session_id text NOT NULL CHECK (char_length(session_id) BETWEEN 1 AND 128),
    requester text NOT NULL CHECK (char_length(requester) BETWEEN 1 AND 255),
    asset text NOT NULL CHECK (char_length(asset) BETWEEN 1 AND 128),
    ticket text NOT NULL CHECK (char_length(ticket) BETWEEN 1 AND 128),
    opened_at bigint NOT NULL,
    closed_at bigint,
    close_reason text,
    recording_frames bigint CHECK (recording_frames >= 2),
    recording_hash bytea CHECK (octet_length(recording_hash) = 32),
    recording_bytes bigint CHECK (recording_bytes >= 0),
    PRIMARY KEY (tenant, session_id),
    CHECK (closed_at IS NULL OR closed_at >= opened_at),
    CHECK ((closed_at IS NULL) = (close_reason IS NULL)),
    CHECK ((recording_frames IS NULL) = (recording_hash IS NULL) AND (recording_hash IS NULL) = (recording_bytes IS NULL)),
    CHECK (recording_hash IS NULL OR closed_at IS NOT NULL)
);
CREATE INDEX remote_shell_sessions_list ON remote_shell_sessions (tenant, opened_at DESC, session_id DESC);
CREATE FUNCTION remote_shell_sessions_append_once() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.closed_at IS NOT NULL
        OR NEW.tenant IS DISTINCT FROM OLD.tenant
        OR NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.requester IS DISTINCT FROM OLD.requester
        OR NEW.asset IS DISTINCT FROM OLD.asset
        OR NEW.ticket IS DISTINCT FROM OLD.ticket
        OR NEW.opened_at IS DISTINCT FROM OLD.opened_at THEN
        RAISE EXCEPTION 'remote_shell_sessions: a row is closed once and its open columns never change';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER remote_shell_sessions_append_once BEFORE UPDATE ON remote_shell_sessions
    FOR EACH ROW EXECUTE FUNCTION remote_shell_sessions_append_once();
