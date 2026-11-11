CREATE TABLE oncall_poller_lease (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    holder text NOT NULL,
    expires_at timestamptz NOT NULL
);
