package com.backend.auth.jwt.refresh;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend.auth.jwt.refresh.RefreshResult.Reason;
import com.backend.auth.jwt.refresh.RefreshResult.Rejected;
import com.backend.auth.jwt.refresh.RefreshResult.Rotated;

/**
 * Rotating refresh tokens with reuse detection.
 *
 * <p>Every refresh marks the presented token as used and issues a successor in the same family. If a
 * used token is ever presented again, two parties hold copies of it (the legitimate client and a thief)
 * and the server cannot tell which is which, so it revokes the whole family and both must log in again.
 */
@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RefreshTokenRepository repository;
    private final RefreshTokenProperties properties;
    private final Clock clock;

    RefreshTokenService(RefreshTokenRepository repository, RefreshTokenProperties properties, Clock clock) {
        this.repository = repository;
        this.properties = properties;
        this.clock = clock;
    }

    /** Starts a new family at login. */
    @Transactional
    public IssuedRefreshToken startFamily(String subject) {
        String value = OpaqueTokens.generate();
        RefreshToken first = RefreshToken.startFamily(subject, OpaqueTokens.sha256Hex(value), clock.instant(),
                properties.absoluteLifetime());
        repository.save(first);
        return issued(value, first);
    }

    @Transactional
    public RefreshResult rotate(String presentedToken) {
        if (!OpaqueTokens.isWellFormed(presentedToken)) {
            return new Rejected(Reason.MALFORMED);
        }
        Optional<RefreshToken> found = repository.findByTokenHashForUpdate(OpaqueTokens.sha256Hex(presentedToken));
        if (found.isEmpty()) {
            return new Rejected(Reason.UNKNOWN);
        }
        RefreshToken current = found.get();
        Instant now = clock.instant();

        if (current.getRevokedAt() != null) {
            return new Rejected(Reason.REVOKED);
        }
        if (current.getUsedAt() != null) {
            return reuseDetected(current, now);
        }
        if (!now.isBefore(current.effectiveExpiry(properties.idleTimeout()))) {
            return new Rejected(Reason.EXPIRED);
        }
        if (repository.markUsed(current.getId(), now) != 1) {
            // Lost a race against a concurrent request with the same token: that is reuse too.
            return reuseDetected(current, now);
        }

        String nextValue = OpaqueTokens.generate();
        RefreshToken next = repository.save(current.successor(OpaqueTokens.sha256Hex(nextValue), now));
        return new Rotated(issued(nextValue, next), current.getSubject());
    }

    /** Logout: revokes the family of the presented token, if it is one of ours. Idempotent. */
    @Transactional
    public void revokeFamilyOf(String presentedToken) {
        if (!OpaqueTokens.isWellFormed(presentedToken)) {
            return;
        }
        repository.findByTokenHash(OpaqueTokens.sha256Hex(presentedToken))
                .ifPresent(token -> revokeFamily(token.getFamilyId(), RevocationReason.LOGOUT));
    }

    @Transactional
    public void revokeFamily(UUID familyId, RevocationReason reason) {
        int revoked = repository.revokeFamily(familyId, reason, clock.instant());
        if (revoked > 0) {
            log.info("Revoked refresh-token family {} ({})", familyId, reason);
        }
    }

    private RefreshResult reuseDetected(RefreshToken reused, Instant now) {
        repository.revokeFamily(reused.getFamilyId(), RevocationReason.REUSE_DETECTED, now);
        // A security event worth alerting on. Log identifiers only, never the token itself.
        log.warn("Refresh token reuse detected: subject={} family={} token={}; family revoked",
                reused.getSubject(), reused.getFamilyId(), reused.getId());
        return new Rejected(Reason.REUSE_DETECTED);
    }

    private IssuedRefreshToken issued(String value, RefreshToken token) {
        return new IssuedRefreshToken(value, token.getFamilyId(), token.getIssuedAt(),
                token.effectiveExpiry(properties.idleTimeout()));
    }
}
