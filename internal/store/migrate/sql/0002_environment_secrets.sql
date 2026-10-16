-- Feature 01: environment secrets and service tokens (spec 01 section 2).

CREATE TABLE secrets (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    project_id      TEXT NOT NULL REFERENCES projects(id),
    environment_id  TEXT NOT NULL REFERENCES environments(id),
    name            TEXT NOT NULL,
    comment         TEXT NOT NULL,
    current_version INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    deleted_at      TEXT
);
CREATE UNIQUE INDEX secrets_env_name ON secrets(environment_id, name) WHERE deleted_at IS NULL;
CREATE INDEX secrets_project ON secrets(project_id);
CREATE INDEX secrets_deleted ON secrets(deleted_at);

CREATE TABLE secret_versions (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    secret_id       TEXT NOT NULL REFERENCES secrets(id),
    version         INTEGER NOT NULL,
    dek_id          TEXT NOT NULL,
    ciphertext      BLOB NOT NULL,
    value_mac       BLOB NOT NULL,
    created_by_kind TEXT NOT NULL,
    created_by_id   TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    restored_from   INTEGER,
    UNIQUE (secret_id, version)
);

CREATE TABLE service_tokens (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    project_id   TEXT NOT NULL REFERENCES projects(id),
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    permission   TEXT NOT NULL CHECK (permission IN ('read', 'read_write')),
    expires_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);
-- Labels are unique among a project's unrevoked tokens.
CREATE UNIQUE INDEX service_tokens_project_name ON service_tokens(project_id, name) WHERE revoked_at IS NULL;

CREATE TABLE service_token_environments (
    token_id       TEXT NOT NULL REFERENCES service_tokens(id),
    environment_id TEXT NOT NULL REFERENCES environments(id),
    PRIMARY KEY (token_id, environment_id)
);
