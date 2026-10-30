CREATE TABLE users (
    id            uuid PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    role          text NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    auth_provider text NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local', 'oidc')),
    auth_hash     text,
    oidc_sub      text UNIQUE,
    vault         jsonb,
    public_key    bytea,
    quota_bytes   bigint,
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE totp_authenticators (
    id        uuid PRIMARY KEY,
    user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name      text NOT NULL,
    secret    text NOT NULL,
    confirmed boolean NOT NULL DEFAULT false,
    last_step bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX totp_user ON totp_authenticators(user_id);

CREATE TABLE recovery_codes (
    id        bigserial PRIMARY KEY,
    user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    used      boolean NOT NULL DEFAULT false
);
CREATE INDEX recovery_codes_user ON recovery_codes(user_id);

CREATE TABLE webauthn_credentials (
    id       uuid PRIMARY KEY,
    user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name     text NOT NULL,
    passkey  jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_user ON webauthn_credentials(user_id);

CREATE TABLE tokens (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('device', 'mfa', 'enroll')),
    token_hash   bytea NOT NULL UNIQUE,
    name         text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz
);
CREATE INDEX tokens_user ON tokens(user_id);

CREATE TABLE invites (
    code_hash  bytea PRIMARY KEY,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_by    uuid REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE nodes (
    id           uuid PRIMARY KEY,
    owner_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id    uuid REFERENCES nodes(id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('file', 'folder', 'kv')),
    enc_name     bytea NOT NULL,
    enc_meta     bytea NOT NULL,
    wrapped_key  bytea NOT NULL,
    head_version uuid,
    size         bigint NOT NULL DEFAULT 0,
    deleted_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX nodes_parent ON nodes(parent_id);
CREATE INDEX nodes_owner_root ON nodes(owner_id) WHERE parent_id IS NULL;
CREATE INDEX nodes_deleted ON nodes(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TABLE versions (
    id             uuid PRIMARY KEY,
    node_id        uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    parent_version uuid,
    size           bigint NOT NULL,
    manifest       bytea NOT NULL,
    device         text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX versions_node ON versions(node_id, created_at);

CREATE TABLE chunks (
    hash        text PRIMARY KEY,
    size        bigint NOT NULL,
    uploaded_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE version_chunks (
    version_id uuid NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    idx        int  NOT NULL,
    hash       text NOT NULL REFERENCES chunks(hash),
    PRIMARY KEY (version_id, idx)
);
CREATE INDEX version_chunks_hash ON version_chunks(hash);

CREATE TABLE shares (
    id         uuid PRIMARY KEY,
    node_id    uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    grantee_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission text NOT NULL CHECK (permission IN ('rw', 'ro')),
    sealed_key bytea NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (node_id, grantee_id)
);
CREATE INDEX shares_grantee ON shares(grantee_id);

CREATE TABLE links (
    id            uuid PRIMARY KEY,
    node_id       uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    token_hash    bytea NOT NULL UNIQUE,
    password_hash text,
    expires_at    timestamptz,
    max_downloads bigint,
    downloads     bigint NOT NULL DEFAULT 0,
    key_envelope  bytea NOT NULL,
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE kv_entries (
    ns_id      uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    key        text NOT NULL,
    value      bytea NOT NULL,
    version    bigint NOT NULL,
    deleted    boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ns_id, key)
);

-- One row per interested user, written at change time, so reads are a simple range scan.
CREATE TABLE changes (
    cursor     bigserial PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id    uuid NOT NULL,
    kind       text NOT NULL,
    version_id uuid,
    kv_key     text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX changes_user_cursor ON changes(user_id, cursor);

CREATE TABLE settings (
    key   text PRIMARY KEY,
    value jsonb NOT NULL
);
