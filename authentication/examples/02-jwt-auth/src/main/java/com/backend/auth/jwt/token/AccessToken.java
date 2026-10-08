package com.backend.auth.jwt.token;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/** A freshly signed access token and the facts the token response needs about it. */
public record AccessToken(String value, Instant issuedAt, Instant expiresAt, List<String> scopes) {

    /** The {@code scope} claim format: space-separated. */
    public String scope() {
        return String.join(" ", scopes);
    }

    public long expiresInSeconds() {
        return Duration.between(issuedAt, expiresAt).toSeconds();
    }
}
