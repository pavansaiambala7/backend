-- API keys: the key itself is never stored. prefix is the non-secret lookup/display part
-- (e.g. ak_live_7Fq2Lx9P); key_hash is HMAC-SHA256(pepper, full key).
CREATE TABLE api_key (
    id            UUID                     PRIMARY KEY,
    owner         VARCHAR(100)             NOT NULL,
    name          VARCHAR(100)             NOT NULL,
    prefix        VARCHAR(16)              NOT NULL,
    key_hash      BINARY(32)               NOT NULL UNIQUE,
    scopes        VARCHAR(500)             NOT NULL,          -- space-separated, like the OAuth scope parameter
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at    TIMESTAMP WITH TIME ZONE NOT NULL,          -- every key expires
    revoked_at    TIMESTAMP WITH TIME ZONE,
    last_used_at  TIMESTAMP WITH TIME ZONE,
    rotated_to    UUID                     REFERENCES api_key (id)
);

CREATE INDEX api_key_prefix_idx ON api_key (prefix);
CREATE INDEX api_key_owner_idx ON api_key (owner);

-- Webhook idempotency: one row per provider event id, so retries are acknowledged but not processed twice.
CREATE TABLE processed_webhook_event (
    event_id     VARCHAR(255)             PRIMARY KEY,
    event_type   VARCHAR(100)             NOT NULL,
    received_at  TIMESTAMP WITH TIME ZONE NOT NULL
);
