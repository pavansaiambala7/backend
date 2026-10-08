package com.backend.auth.apikeys.webhook;

import java.time.Instant;

/**
 * Remembers messages that were already accepted. With several application instances this must be shared,
 * for example Redis {@code SET <key> 1 NX EXAT <expiresAt>}, which does the same check-and-set atomically.
 */
public interface ReplayCache {

    /**
     * Atomically records {@code key} until {@code expiresAt}.
     *
     * @return true the first time a key is seen, false if it is already recorded and not yet expired
     */
    boolean firstSeen(String key, Instant expiresAt);
}
