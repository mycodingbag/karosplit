CREATE TABLE IF NOT EXISTS users (
  id           BIGSERIAL PRIMARY KEY,
  name         TEXT NOT NULL,
  mobile       TEXT NOT NULL UNIQUE,          -- e.g. +919876543210
  pin_hash     TEXT NOT NULL,                 -- bcrypt hash, never the PIN itself
  failed_tries INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,                -- SHA-256 of the cookie value
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

-- One row per user holding { trips, activeTripId }, the same shape app.html already uses
CREATE TABLE IF NOT EXISTS user_data (
  user_id    BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  state      JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
