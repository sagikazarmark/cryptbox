CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email BLOB,
    email_lookup BLOB,
    CHECK ((email IS NULL) = (email_lookup IS NULL))
);
CREATE INDEX IF NOT EXISTS users_email_lookup ON users (email_lookup);
