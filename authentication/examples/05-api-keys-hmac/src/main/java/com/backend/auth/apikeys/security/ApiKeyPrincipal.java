package com.backend.auth.apikeys.security;

import java.util.UUID;

import org.springframework.security.core.AuthenticatedPrincipal;

/**
 * Who is calling once a key has been verified: the owning account, plus which key (for audit logs and
 * last-used tracking). Contains nothing secret.
 */
public record ApiKeyPrincipal(UUID keyId, String owner, String keyPrefix) implements AuthenticatedPrincipal {

    @Override
    public String getName() {
        return owner;
    }
}
