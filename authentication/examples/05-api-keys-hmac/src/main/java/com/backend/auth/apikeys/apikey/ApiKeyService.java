package com.backend.auth.apikeys.apikey;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend.auth.apikeys.apikey.ApiKeyExceptions.InvalidKeyRequest;
import com.backend.auth.apikeys.apikey.ApiKeyExceptions.KeyNotFound;
import com.backend.auth.apikeys.apikey.ApiKeyExceptions.KeyNotRotatable;

/** Key management: create (show once), list, revoke, rotate with overlap. Every operation is scoped to one owner. */
@Service
public class ApiKeyService {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyService.class);

    private final ApiKeyRepository repository;
    private final ApiKeyFormat format;
    private final ApiKeyHasher hasher;
    private final ApiKeyProperties properties;
    private final Clock clock;

    ApiKeyService(ApiKeyRepository repository, ApiKeyFormat format, ApiKeyHasher hasher,
            ApiKeyProperties properties, Clock clock) {
        this.repository = repository;
        this.format = format;
        this.hasher = hasher;
        this.properties = properties;
        this.clock = clock;
    }

    /** @param lifetime null for the configured default */
    @Transactional
    public IssuedApiKey create(String owner, String name, Set<String> scopes, Duration lifetime) {
        Set<String> unknown = new TreeSet<>(scopes);
        unknown.removeAll(properties.scopes());
        if (scopes.isEmpty() || !unknown.isEmpty()) {
            throw new InvalidKeyRequest("Unknown or missing scopes " + unknown + "; allowed: " + new TreeSet<>(properties.scopes()));
        }
        Duration effectiveLifetime = lifetime == null ? properties.defaultLifetime() : lifetime;
        if (!effectiveLifetime.isPositive() || effectiveLifetime.compareTo(properties.maxLifetime()) > 0) {
            throw new InvalidKeyRequest("Key lifetime must be positive and at most " + properties.maxLifetime().toDays() + " days");
        }
        return issue(owner, name, scopes, effectiveLifetime);
    }

    public List<ApiKey> list(String owner) {
        return repository.findByOwner(owner);
    }

    public ApiKey get(String owner, UUID id) {
        return repository.findByIdAndOwner(id, owner).orElseThrow(() -> new KeyNotFound(id));
    }

    /** Idempotent: revoking a revoked key returns it unchanged. Takes effect on the very next request (no cache). */
    @Transactional
    public ApiKey revoke(String owner, UUID id) {
        get(owner, id);
        if (repository.revoke(id, owner, now())) {
            log.info("API key revoked: id={} owner={}", id, owner);
        }
        return get(owner, id);
    }

    /**
     * Issues a successor with the same name, scopes and lifetime, and lets the old key live on only for the
     * overlap window, long enough for the client to deploy the new key without downtime. One successor per key:
     * a second rotation fails, so a leaked key cannot be used to keep minting fresh ones.
     */
    @Transactional
    public ApiKeyRotation rotate(String owner, UUID id) {
        Instant now = now();
        ApiKey old = get(owner, id);
        if (old.statusAt(now) != ApiKeyStatus.ACTIVE) {
            throw new KeyNotRotatable("Only active keys can be rotated; create a new key instead");
        }
        if (old.rotatedTo() != null) {
            throw new KeyNotRotatable("This key was already rotated to " + old.rotatedTo());
        }
        Duration lifetime = Duration.between(old.createdAt(), old.expiresAt());
        IssuedApiKey replacement = issue(owner, old.name(), old.scopes(), min(lifetime, properties.maxLifetime()));

        // Never extend the old key: if it would expire before the overlap ends anyway, keep that earlier date.
        Instant overlapEnd = min(old.expiresAt(), now.plus(properties.rotationOverlap()));
        if (!repository.markRotated(id, owner, replacement.key().id(), overlapEnd)) {
            throw new KeyNotRotatable("The key was rotated or revoked concurrently");   // rolls back the new key
        }
        log.info("API key rotated: id={} successor={} old key expires at {}", id, replacement.key().id(), overlapEnd);
        return new ApiKeyRotation(replacement, get(owner, id));
    }

    private IssuedApiKey issue(String owner, String name, Set<String> scopes, Duration lifetime) {
        Instant now = now();
        String secret = format.generate();
        String prefix = format.lookupPrefix(secret).orElseThrow();
        ApiKey key = new ApiKey(UUID.randomUUID(), owner, name, prefix, hasher.hash(secret), scopes,
                now, now.plus(lifetime), null, null, null);
        repository.insert(key);
        log.info("API key created: id={} owner={} prefix={} scopes={}", key.id(), owner, prefix, key.scopes());
        return new IssuedApiKey(secret, key);
    }

    /** Whole seconds: what the create response shows is exactly what later reads from the database return. */
    private Instant now() {
        return clock.instant().truncatedTo(ChronoUnit.SECONDS);
    }

    private static <T extends Comparable<T>> T min(T a, T b) {
        return a.compareTo(b) <= 0 ? a : b;
    }
}
