CREATE TABLE users (
    id            BIGSERIAL   PRIMARY KEY,
    username      TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspaces (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
    workspace_id UUID   NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role         TEXT   NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE INDEX workspace_members_user ON workspace_members (user_id);

CREATE TABLE devices (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        UUID        NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name                TEXT        NOT NULL,
    proxy_username      TEXT        NOT NULL UNIQUE,
    proxy_password_hash TEXT        NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX devices_workspace ON devices (workspace_id);

CREATE TABLE domains (
    id           BIGSERIAL PRIMARY KEY,
    workspace_id UUID      NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scheme       SMALLINT  NOT NULL,
    domain       TEXT      NOT NULL,
    -- NULL marks a paths-only domain: neither approved nor blocked as a whole.
    approved     BOOLEAN,
    UNIQUE (workspace_id, scheme, domain)
);

CREATE TABLE paths (
    id        BIGSERIAL PRIMARY KEY,
    domain_id BIGINT    NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    path      TEXT      NOT NULL,
    approved  BOOLEAN   NOT NULL,
    UNIQUE (domain_id, path)
);

CREATE TABLE domain_metadata (
    domain_id   BIGINT      PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    title       TEXT,
    icon        TEXT,
    fetched_at  TIMESTAMPTZ,
    fetch_error TEXT
);

CREATE TABLE path_metadata (
    path_id     BIGINT      PRIMARY KEY REFERENCES paths(id) ON DELETE CASCADE,
    title       TEXT,
    fetched_at  TIMESTAMPTZ,
    fetch_error TEXT
);

CREATE TABLE videos (
    id           BIGSERIAL PRIMARY KEY,
    workspace_id UUID      NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    url          TEXT      NOT NULL,
    download     BOOLEAN   NOT NULL,
    UNIQUE (workspace_id, url)
);

CREATE TABLE video_metadata (
    video_id    BIGINT      PRIMARY KEY REFERENCES videos(id) ON DELETE CASCADE,
    title       TEXT,
    uploader    TEXT,
    duration    INTEGER,
    thumbnail   TEXT,
    fetched_at  TIMESTAMPTZ,
    fetch_error TEXT
);

-- No foreign keys: audit rows must outlive the users, devices and workspaces they mention.
CREATE TABLE audit_log (
    id           BIGSERIAL   PRIMARY KEY,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    workspace_id UUID,
    actor_kind   TEXT        NOT NULL CHECK (actor_kind IN ('user', 'device', 'cli', 'anonymous')),
    actor_id     TEXT,
    actor_label  TEXT        NOT NULL,
    action       TEXT        NOT NULL,
    target_kind  TEXT,
    target_id    TEXT,
    details      JSONB       NOT NULL DEFAULT '{}',
    ip           INET,
    user_agent   TEXT
);

CREATE INDEX audit_log_workspace_time ON audit_log (workspace_id, occurred_at DESC);

-- Guards against application bugs, not against the database owner, who can drop the trigger.
CREATE FUNCTION audit_log_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('sieve.audit_purge', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_log is append-only';
END
$$;

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_guard();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_guard();
