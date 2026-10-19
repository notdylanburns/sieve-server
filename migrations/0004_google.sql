-- Users who sign in with Google have no password, and are found by Google's stable subject id
-- rather than their email, which can change.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN google_sub TEXT UNIQUE;
