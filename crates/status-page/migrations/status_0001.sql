CREATE TABLE status_incidents (
    tenant text NOT NULL,
    id bigint GENERATED ALWAYS AS IDENTITY,
    service text NOT NULL CHECK (char_length(service) BETWEEN 1 AND 128),
    public_title text NOT NULL CHECK (char_length(public_title) BETWEEN 1 AND 200),
    published boolean NOT NULL,
    started_at bigint NOT NULL,
    resolved_at bigint,
    version bigint NOT NULL DEFAULT 0,
    internal_note text NOT NULL DEFAULT '' CHECK (char_length(internal_note) <= 2000),
    PRIMARY KEY (tenant, id)
);
CREATE INDEX status_incidents_published ON status_incidents (tenant, started_at DESC, id DESC) WHERE published;
CREATE TABLE status_incident_updates (
    tenant text NOT NULL,
    seq bigint GENERATED ALWAYS AS IDENTITY,
    incident bigint NOT NULL,
    at bigint NOT NULL,
    message text NOT NULL CHECK (char_length(message) BETWEEN 1 AND 500),
    internal_note text NOT NULL DEFAULT '' CHECK (char_length(internal_note) <= 2000),
    PRIMARY KEY (tenant, seq),
    FOREIGN KEY (tenant, incident) REFERENCES status_incidents (tenant, id)
);
CREATE INDEX status_incident_updates_incident ON status_incident_updates (tenant, incident, at);
