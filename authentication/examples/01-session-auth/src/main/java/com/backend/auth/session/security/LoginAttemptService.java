package com.backend.auth.session.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

/**
 * Counts failed logins per (username + IP), per username and per IP, and blocks a key with
 * exponential backoff once it crosses its threshold.
 *
 * <p>Usernames are counted whether or not the account exists. Spring Security reports an unknown
 * username as the same {@code BadCredentialsException} as a wrong password, so this service cannot
 * tell them apart, and neither can an attacker watching when the throttle starts.
 *
 * <p>State is in memory to keep the example self-contained. With more than one instance, keep the
 * counters in a shared store (for example Redis with key TTLs) so every node sees the same numbers.
 */
@Component
public class LoginAttemptService {

    /** Above this many keys, stale entries are purged so random usernames cannot exhaust memory. */
    private static final int PURGE_THRESHOLD = 100_000;
    private static final int MAX_USERNAME_LENGTH = 320;
    private static final int MAX_DOUBLINGS = 20;

    private record Counter(int failures, Instant lastFailure, Instant blockedUntil) {}

    private record Key(String value, int threshold) {}

    private final Map<String, Counter> counters = new ConcurrentHashMap<>();
    private final LoginThrottleProperties properties;
    private final Clock clock;

    LoginAttemptService(LoginThrottleProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /** How long this username/IP pair must wait before the next attempt, if it is blocked at all. */
    public Optional<Duration> retryAfter(@Nullable String username, String remoteAddress) {
        Instant now = clock.instant();
        return keysFor(username, remoteAddress).stream()
                .map(key -> counters.get(key.value()))
                .filter(Objects::nonNull)
                .map(counter -> Duration.between(now, counter.blockedUntil()))
                .filter(Duration::isPositive)
                .max(Comparator.naturalOrder());
    }

    public void recordFailure(@Nullable String username, String remoteAddress) {
        Instant now = clock.instant();
        purgeStaleCountersIfNeeded(now);
        for (Key key : keysFor(username, remoteAddress)) {
            counters.compute(key.value(), (k, previous) -> nextCounter(previous, key.threshold(), now));
        }
    }

    public void recordSuccess(String username, String remoteAddress) {
        // The per-IP counter is deliberately NOT reset: otherwise an attacker who owns one valid
        // account could log into it between guesses and wipe the counter for their IP.
        String normalized = normalize(username);
        counters.remove(userKey(normalized));
        counters.remove(userAndIpKey(normalized, remoteAddress));
    }

    @EventListener
    void onBadCredentials(AuthenticationFailureBadCredentialsEvent event) {
        recordFailure(event.getAuthentication().getName(), remoteAddress(event.getAuthentication()));
    }

    @EventListener
    void onSuccess(AuthenticationSuccessEvent event) {
        recordSuccess(event.getAuthentication().getName(), remoteAddress(event.getAuthentication()));
    }

    private Counter nextCounter(@Nullable Counter previous, int threshold, Instant now) {
        int failures = (previous == null || isStale(previous, now)) ? 1 : previous.failures() + 1;
        Instant blockedUntil = failures < threshold ? now : now.plus(blockDuration(failures - threshold));
        return new Counter(failures, now, blockedUntil);
    }

    /** 0 extra failures: initialBlock; each further failure doubles it, capped at maxBlock. */
    private Duration blockDuration(int failuresBeyondThreshold) {
        Duration block = properties.initialBlock().multipliedBy(1L << Math.min(failuresBeyondThreshold, MAX_DOUBLINGS));
        return block.compareTo(properties.maxBlock()) > 0 ? properties.maxBlock() : block;
    }

    private boolean isStale(Counter counter, Instant now) {
        Instant forgetAt = counter.lastFailure().plus(properties.forgetAfter());
        Instant expiresAt = forgetAt.isAfter(counter.blockedUntil()) ? forgetAt : counter.blockedUntil();
        return !now.isBefore(expiresAt);
    }

    private void purgeStaleCountersIfNeeded(Instant now) {
        if (counters.size() > PURGE_THRESHOLD) {
            counters.values().removeIf(counter -> isStale(counter, now));
        }
    }

    private List<Key> keysFor(@Nullable String username, String remoteAddress) {
        String normalized = normalize(username);
        return List.of(
                new Key(userAndIpKey(normalized, remoteAddress), properties.maxFailuresPerUserAndIp()),
                new Key(userKey(normalized), properties.maxFailuresPerUser()),
                new Key(ipKey(remoteAddress), properties.maxFailuresPerIp()));
    }

    private static String userKey(String normalizedUsername) {
        return "user:" + normalizedUsername;
    }

    private static String userAndIpKey(String normalizedUsername, String remoteAddress) {
        return "user-ip:" + normalizedUsername + "|" + remoteAddress;
    }

    private static String ipKey(String remoteAddress) {
        return "ip:" + remoteAddress;
    }

    /** Same normalization as account lookup (trim + lower case), so "Alice " and "alice" share a counter. */
    private static String normalize(@Nullable String username) {
        if (username == null) {
            return "";
        }
        String normalized = username.trim().toLowerCase(Locale.ROOT);
        return normalized.length() > MAX_USERNAME_LENGTH ? normalized.substring(0, MAX_USERNAME_LENGTH) : normalized;
    }

    private static String remoteAddress(Authentication authentication) {
        // getRemoteAddr() is the real client only if forwarded headers come from a trusted proxy
        // (server.forward-headers-strategy=native in the prod profile).
        return authentication.getDetails() instanceof WebAuthenticationDetails details
                && details.getRemoteAddress() != null ? details.getRemoteAddress() : "unknown";
    }
}
