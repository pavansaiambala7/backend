package com.backend.auth.apikeys.apikey;

import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Checks a presented key on every request. Cheap checks first: format and checksum (no I/O), then one indexed
 * lookup by prefix, then a constant-time comparison of HMAC digests, then revocation and expiry.
 */
@Component
public class ApiKeyVerifier {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyVerifier.class);

    public enum Outcome { VALID, MALFORMED, UNKNOWN, REVOKED, EXPIRED }

    /** @param key the matching key when {@code outcome} is VALID, otherwise null */
    public record Verification(Outcome outcome, ApiKey key) {

        public boolean valid() {
            return outcome == Outcome.VALID;
        }
    }

    private final ApiKeyFormat format;
    private final ApiKeyHasher hasher;
    private final ApiKeyRepository repository;
    private final ApiKeyProperties properties;
    private final Clock clock;

    ApiKeyVerifier(ApiKeyFormat format, ApiKeyHasher hasher, ApiKeyRepository repository,
            ApiKeyProperties properties, Clock clock) {
        this.format = format;
        this.hasher = hasher;
        this.repository = repository;
        this.properties = properties;
        this.clock = clock;
    }

    public Verification verify(String presented) {
        Optional<String> prefix = format.lookupPrefix(presented);
        if (prefix.isEmpty()) {
            // Never log the value: it may be a password or another system's token pasted by mistake.
            log.info("API key rejected: malformed or bad checksum");
            return new Verification(Outcome.MALFORMED, null);
        }

        byte[] presentedHash = hasher.hash(presented);
        Optional<ApiKey> match = repository.findByPrefix(prefix.get()).stream()
                // Comparing keyed digests instead of raw keys already leaves an attacker nothing useful to time;
                // MessageDigest.isEqual (no early exit on the first differing byte) removes the rest for free.
                .filter(candidate -> MessageDigest.isEqual(candidate.keyHash(), presentedHash))
                .findFirst();
        if (match.isEmpty()) {
            log.info("API key rejected: unknown key, prefix={}", prefix.get());
            return new Verification(Outcome.UNKNOWN, null);
        }

        ApiKey key = match.get();
        Instant now = clock.instant();
        switch (key.statusAt(now)) {
            case REVOKED -> {
                log.info("API key rejected: revoked, id={} prefix={}", key.id(), key.prefix());
                return new Verification(Outcome.REVOKED, null);
            }
            case EXPIRED -> {
                log.info("API key rejected: expired, id={} prefix={}", key.id(), key.prefix());
                return new Verification(Outcome.EXPIRED, null);
            }
            case ACTIVE -> {
                recordUse(key, now);
                return new Verification(Outcome.VALID, key);
            }
        }
        throw new IllegalStateException("Unhandled status for key " + key.id());
    }

    /** At most one write per key per granularity window: a write on every request would not scale. */
    private void recordUse(ApiKey key, Instant now) {
        Instant threshold = now.minus(properties.lastUsedGranularity());
        if (key.lastUsedAt() == null || key.lastUsedAt().isBefore(threshold)) {
            repository.recordUse(key.id(), now.truncatedTo(ChronoUnit.SECONDS), threshold);
        }
    }
}
