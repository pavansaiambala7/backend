package com.backend.auth.apikeys.admin;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.backend.auth.apikeys.apikey.ApiKey;
import com.backend.auth.apikeys.apikey.ApiKeyStatus;

/** What listings show about a key: the prefix to recognize it, never the key or its hash. */
public record ApiKeyView(
        UUID id,
        String name,
        String prefix,
        Set<String> scopes,
        ApiKeyStatus status,
        Instant createdAt,
        Instant expiresAt,
        Instant lastUsedAt,
        Instant revokedAt,
        UUID rotatedTo) {

    static ApiKeyView of(ApiKey key, Instant now) {
        return new ApiKeyView(key.id(), key.name(), key.prefix(), key.scopes(), key.statusAt(now),
                key.createdAt(), key.expiresAt(), key.lastUsedAt(), key.revokedAt(), key.rotatedTo());
    }
}
