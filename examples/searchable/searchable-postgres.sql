CREATE TABLE IF NOT EXISTS users (
    id BIGINT PRIMARY KEY,
    email BYTEA,
    email_lookup BYTEA,
    CHECK ((email IS NULL) = (email_lookup IS NULL))
);
CREATE INDEX IF NOT EXISTS users_email_lookup ON users (email_lookup);
