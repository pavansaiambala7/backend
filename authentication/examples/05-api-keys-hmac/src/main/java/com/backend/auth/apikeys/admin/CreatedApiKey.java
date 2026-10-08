package com.backend.auth.apikeys.admin;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.backend.auth.apikeys.apikey.IssuedApiKey;

/** The only response that ever contains a full key. */
public record CreatedApiKey(
        UUID id,
        String name,
        String key,
        String prefix,
        Set<String> scopes,
        Instant createdAt,
        Instant expiresAt,
        String notice) {

    static CreatedApiKey of(IssuedApiKey issued) {
        var key = issued.key();
        return new CreatedApiKey(key.id(), key.name(), issued.secret(), key.prefix(), key.scopes(),
                key.createdAt(), key.expiresAt(),
                "Store this key in your secret manager now. It is shown only once and cannot be recovered.");
    }

    @Override
    public String toString() {
        return "CreatedApiKey[id=" + id + ", prefix=" + prefix + ", key=<redacted>]";
    }
}
