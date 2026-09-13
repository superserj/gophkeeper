-- +goose Up
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    login         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt_auth     BYTEA NOT NULL,
    salt_data     BYTEA NOT NULL,
    kdf_version   INT NOT NULL DEFAULT 1,
    verifier      BYTEA NOT NULL,
    revision      BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS secrets (
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    id         UUID NOT NULL,
    revision   BIGINT NOT NULL,
    payload    BYTEA NOT NULL,
    deleted    BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
);

CREATE INDEX IF NOT EXISTS secrets_user_revision_idx ON secrets (user_id, revision);

-- +goose Down
DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS users;
