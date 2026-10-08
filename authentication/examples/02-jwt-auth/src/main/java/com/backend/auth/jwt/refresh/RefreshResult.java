package com.backend.auth.jwt.refresh;

/**
 * Outcome of presenting a refresh token. A result object instead of an exception, so that a family
 * revoked during the transaction is committed rather than rolled back.
 */
public sealed interface RefreshResult {

    record Rotated(IssuedRefreshToken next, String subject) implements RefreshResult {
    }

    /** The caller only learns "rejected"; the reason is for logs and tests. */
    record Rejected(Reason reason) implements RefreshResult {
    }

    enum Reason {
        MALFORMED,
        UNKNOWN,
        EXPIRED,
        REVOKED,
        REUSE_DETECTED
    }
}
