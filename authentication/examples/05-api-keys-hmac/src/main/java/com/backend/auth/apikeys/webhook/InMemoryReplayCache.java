package com.backend.auth.apikeys.webhook;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Single-instance replay cache. Entries are kept only until the timestamp they belong to falls outside the
 * tolerance window; after that the timestamp check rejects a replay on its own, so memory stays bounded by
 * the number of genuine deliveries per window. (Only verified messages are ever recorded, so an attacker
 * without the secret cannot fill it.)
 */
public final class InMemoryReplayCache implements ReplayCache {

    private final ConcurrentMap<String, Instant> entries = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryReplayCache(Clock clock) {
        this.clock = clock;
    }

    @Override
    public boolean firstSeen(String key, Instant expiresAt) {
        Instant now = clock.instant();
        entries.values().removeIf(expiry -> !expiry.isAfter(now));
        // putIfAbsent is the atomic check-and-set: of two concurrent identical deliveries, exactly one wins.
        return entries.putIfAbsent(key, expiresAt) == null;
    }

    int size() {
        return entries.size();
    }
}
