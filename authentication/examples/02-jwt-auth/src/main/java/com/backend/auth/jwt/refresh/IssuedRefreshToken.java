package com.backend.auth.jwt.refresh;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * A new refresh token. {@code value} goes to the client exactly once (in the cookie) and is never stored.
 *
 * @param expiresAt when this token stops working: the idle timeout or the end of the family, whichever is first
 */
public record IssuedRefreshToken(String value, UUID familyId, Instant issuedAt, Instant expiresAt) {

    public Duration lifetime() {
        return Duration.between(issuedAt, expiresAt);
    }
}
