-- Applied by Spring Boot on startup (embedded database). In production, manage the schema with
-- Flyway or Liquibase and keep spring.jpa.hibernate.ddl-auto=validate.
create table refresh_token (
    id            uuid                        primary key,
    -- One family per login. Every rotation adds a row to the same family; revoking the family
    -- (logout, reuse detected) kills the whole chain at once.
    family_id     uuid                        not null,
    subject       varchar(100)                not null,
    -- SHA-256 (hex) of the token. The token itself is never stored, so a database leak yields
    -- nothing usable. A fast hash is enough: the token is 256 random bits, nothing to brute-force.
    token_hash    varchar(64)                 not null,
    parent_id     uuid,                                     -- the token this one replaced
    issued_at     timestamp(6) with time zone not null,
    expires_at    timestamp(6) with time zone not null,     -- absolute end of the family
    used_at       timestamp(6) with time zone,              -- set when rotated; a second use is reuse
    revoked_at    timestamp(6) with time zone,
    revoke_reason varchar(32),
    constraint uk_refresh_token_hash unique (token_hash)
);

create index ix_refresh_token_family on refresh_token (family_id);
