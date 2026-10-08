package com.backend.auth.apikeys.apikey;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * One row of the {@code api_key} table. The key itself is never stored: only {@code prefix} (lookup and
 * display) and {@code keyHash} (HMAC-SHA256 with the pepper).
 *
 * @param owner     the account (tenant) the key acts for
 * @param rotatedTo the replacement key, once this one has been rotated; it then expires at the end of the overlap
 */
public record ApiKey(
        UUID id,
        String owner,
        String name,
        String prefix,
        byte[] keyHash,
        Set<String> scopes,
        Instant createdAt,
        Instant expiresAt,
        Instant revokedAt,
        Instant lastUsedAt,
        UUID rotatedTo) {

    public ApiKey {
        scopes = Collections.unmodifiableSortedSet(new TreeSet<>(scopes));
    }

    public ApiKeyStatus statusAt(Instant now) {
        if (revokedAt != null) {
            return ApiKeyStatus.REVOKED;
        }
        if (!now.isBefore(expiresAt)) {
            return ApiKeyStatus.EXPIRED;
        }
        return ApiKeyStatus.ACTIVE;
    }

    /** Never print the hash: it is not the key, but there is no reason for it to reach a log either. */
    @Override
    public String toString() {
        return "ApiKey[id=" + id + ", owner=" + owner + ", prefix=" + prefix + ", scopes=" + scopes + "]";
    }
}
