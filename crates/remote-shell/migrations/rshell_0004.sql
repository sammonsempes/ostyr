ALTER TABLE remote_shell_sessions
    ADD CONSTRAINT remote_shell_sessions_session_id_grammar
        CHECK (session_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$' AND octet_length(session_id) = char_length(session_id)),
    ADD CONSTRAINT remote_shell_sessions_asset_grammar
        CHECK (asset ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$' AND octet_length(asset) = char_length(asset)),
    ADD CONSTRAINT remote_shell_sessions_ticket_grammar
        CHECK (ticket ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$' AND octet_length(ticket) = char_length(ticket)),
    ADD CONSTRAINT remote_shell_sessions_requester_grammar
        CHECK (requester ~ '^[A-Za-z0-9_.@:+/=|-]{1,255}$' AND octet_length(requester) = char_length(requester));
