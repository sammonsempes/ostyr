ALTER TABLE remote_shell_sessions ADD CONSTRAINT remote_shell_sessions_close_reason_token
    CHECK (close_reason IS NULL OR close_reason IN ('idle_timeout', 'max_duration', 'recording_failed', 'channel_dead', 'user_close', 'clock_skew'));
CREATE FUNCTION remote_shell_sessions_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'remote_shell_sessions: rows are evidence and are never truncated';
END
$$;
CREATE TRIGGER remote_shell_sessions_no_truncate BEFORE TRUNCATE ON remote_shell_sessions
    FOR EACH STATEMENT EXECUTE FUNCTION remote_shell_sessions_no_truncate();
