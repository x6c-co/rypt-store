-- Core schema (spec 00-core sections 5.4, 6.2, 8).
-- IDs are UUIDv7 text, timestamps fixed-width RFC 3339 UTC text, booleans
-- INTEGER 0/1, JSON TEXT (core 4.3).

-- batch_guards turns a precondition into a constraint failure inside one
-- transactional batch: a guard row is inserted with ok = (condition), which
-- fails the CHECK and rolls the batch back when the condition is false, and
-- is deleted again in the same batch.
CREATE TABLE batch_guards (
    k  TEXT PRIMARY KEY,
    ok INTEGER NOT NULL CHECK (ok = 1)
);

CREATE TABLE instance (
    id                     TEXT PRIMARY KEY,
    singleton              INTEGER NOT NULL DEFAULT 1 UNIQUE CHECK (singleton = 1),
    created_at             TEXT NOT NULL,
    setup_completed_at     TEXT,
    setup_token_hash       TEXT,
    setup_token_expires_at TEXT
);

CREATE TABLE users (
    id                TEXT PRIMARY KEY,
    email             TEXT NOT NULL UNIQUE,
    display_name      TEXT NOT NULL,
    password_hash     TEXT NOT NULL,
    is_instance_admin INTEGER NOT NULL DEFAULT 0,
    disabled_at       TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE user_totp (
    user_id           TEXT PRIMARY KEY REFERENCES users(id),
    secret_ciphertext BLOB NOT NULL,
    confirmed_at      TEXT
);

CREATE TABLE user_recovery_codes (
    id        TEXT PRIMARY KEY,
    user_id   TEXT NOT NULL REFERENCES users(id),
    code_hash TEXT NOT NULL,
    used_at   TEXT
);
CREATE INDEX user_recovery_codes_user ON user_recovery_codes(user_id);

CREATE TABLE webauthn_credentials (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id),
    credential_id BLOB NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL,
    transports    TEXT NOT NULL,
    name          TEXT NOT NULL,
    data          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id);

CREATE TABLE sessions (
    id_hash       TEXT PRIMARY KEY,
    public_id     TEXT NOT NULL UNIQUE,
    user_id       TEXT NOT NULL REFERENCES users(id),
    kind          TEXT NOT NULL CHECK (kind IN ('web', 'cli')),
    mfa_satisfied INTEGER NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    ip            TEXT,
    user_agent    TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE device_auth_requests (
    device_code_hash TEXT PRIMARY KEY,
    user_code        TEXT NOT NULL UNIQUE,
    user_id          TEXT,
    state            TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    client_name      TEXT
);

CREATE TABLE password_resets (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE TABLE tenant_memberships (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    user_id    TEXT NOT NULL REFERENCES users(id),
    role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX tenant_memberships_user ON tenant_memberships(user_id);

CREATE TABLE invitations (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    email       TEXT NOT NULL,
    role        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TEXT NOT NULL,
    accepted_at TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX invitations_tenant ON invitations(tenant_id);

CREATE TABLE projects (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL,
    key_mode   TEXT NOT NULL CHECK (key_mode IN ('A', 'B', 'C')),
    created_at TEXT NOT NULL,
    deleted_at TEXT
);
-- Slugs are unique among live projects, so a deleted project's slug can be reused.
CREATE UNIQUE INDEX projects_tenant_slug ON projects(tenant_id, slug) WHERE deleted_at IS NULL;

CREATE TABLE environments (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    project_id TEXT NOT NULL REFERENCES projects(id),
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL,
    position   INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (project_id, slug)
);

CREATE TABLE key_wraps (
    id           TEXT PRIMARY KEY,
    key_id       TEXT NOT NULL,
    key_kind     TEXT NOT NULL CHECK (key_kind IN ('instance', 'root', 'project', 'dek')),
    tenant_id    TEXT,
    project_id   TEXT,
    wrapper_kind TEXT NOT NULL CHECK (wrapper_kind IN ('provider', 'root', 'project')),
    wrapper_ref  TEXT NOT NULL,
    key_version  TEXT,
    ciphertext   BLOB NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('pending', 'active', 'retired')),
    created_at   TEXT NOT NULL,
    -- retired_at starts the keys.retired_wrap_retention clock (core 5.7).
    retired_at   TEXT
);
-- Exactly one active wrap per logical key (core 5.4).
CREATE UNIQUE INDEX key_wraps_one_active ON key_wraps(key_id) WHERE state = 'active';
-- At most one active instance key and one active root key.
CREATE UNIQUE INDEX key_wraps_one_ik_rk ON key_wraps(key_kind) WHERE state = 'active' AND key_kind IN ('instance', 'root');
CREATE INDEX key_wraps_project ON key_wraps(project_id, state);
CREATE INDEX key_wraps_wrapper ON key_wraps(wrapper_kind, state);

CREATE TABLE key_migrations (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (kind IN ('provider', 'mode', 'rotate')),
    params         TEXT NOT NULL,
    state          TEXT NOT NULL,
    projects_total INTEGER NOT NULL,
    projects_done  INTEGER NOT NULL,
    cursor         TEXT,
    error          TEXT,
    started_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    finished_at    TEXT
);

CREATE TABLE provider_op_counts (
    month    TEXT NOT NULL,
    provider TEXT NOT NULL,
    op       TEXT NOT NULL,
    count    INTEGER NOT NULL,
    PRIMARY KEY (month, provider, op)
);

CREATE TABLE audit_chains (
    chain_id    TEXT PRIMARY KEY,
    head_seq    INTEGER NOT NULL,
    head_hash   TEXT NOT NULL,
    anchor_seq  INTEGER NOT NULL,
    anchor_hash TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE audit_events (
    id                  TEXT PRIMARY KEY,
    chain_id            TEXT NOT NULL,
    seq                 INTEGER NOT NULL,
    ts                  TEXT NOT NULL,
    actor_kind          TEXT NOT NULL,
    actor_id            TEXT,
    action              TEXT NOT NULL,
    target_kind         TEXT,
    target_id           TEXT,
    project_id          TEXT,
    environment_id      TEXT,
    result              TEXT NOT NULL CHECK (result IN ('success', 'denied', 'error')),
    ip                  TEXT,
    user_agent          TEXT,
    request_id          TEXT,
    provider_request_id TEXT,
    metadata            TEXT NOT NULL,
    prev_hash           TEXT NOT NULL,
    hash                TEXT NOT NULL,
    UNIQUE (chain_id, seq)
);
CREATE INDEX audit_events_chain_ts ON audit_events(chain_id, ts);

CREATE TABLE jobs (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    state      TEXT NOT NULL,
    run_after  TEXT NOT NULL,
    attempts   INTEGER NOT NULL,
    last_error TEXT,
    payload    TEXT NOT NULL,
    dedupe_key TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX jobs_dedupe ON jobs(dedupe_key) WHERE state = 'pending' AND dedupe_key IS NOT NULL;
CREATE INDEX jobs_due ON jobs(state, run_after);
