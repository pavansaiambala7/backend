package com.backend.auth.mfa.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;

import org.springframework.stereotype.Component;

/**
 * Limits wrong second-factor codes per account.
 *
 * <p>A 6-digit code with a window of three time steps is guessed with probability 3 in 1,000,000 per try, so an
 * unthrottled endpoint falls to a script within hours. The limit is per <em>account</em>, not per session or IP:
 * whoever is guessing already knows the password and can open new sessions from many addresses at will. TOTP
 * codes, recovery codes and enrollment confirmations share one budget, so switching methods gains nothing.
 *
 * <p>After {@code maxFailures} consecutive failures the account's second factor is blocked for
 * {@code initialBlock}, doubling with each further failure up to {@code maxBlock}. Blocks are temporary on purpose:
 * a permanent lockout would let anyone who knows a password lock the real user out.
 *
 * <p>In memory, so it only covers this instance; with several instances keep the counters in Redis or the database.
 */
@Component
public class SecondFactorThrottle {

    private final Map<String, Attempts> attemptsByUser = new ConcurrentHashMap<>();
    private final SecondFactorProperties properties;
    private final Clock clock;

    public SecondFactorThrottle(SecondFactorProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Runs one code check under the limit.
     *
     * @return the result of {@code verification}
     * @throws SecondFactorThrottledException if the account is blocked; {@code verification} is not run, so even
     *                                        the correct code is refused until the block ends
     */
    public boolean attempt(String username, BooleanSupplier verification) {
        Attempts attempts = attemptsByUser.computeIfAbsent(username, key -> new Attempts());
        synchronized (attempts) {
            Instant now = clock.instant();
            if (now.isBefore(attempts.blockedUntil)) {
                throw new SecondFactorThrottledException(Duration.between(now, attempts.blockedUntil));
            }
            // Counted as a failure before the check runs, so parallel guesses cannot exceed the budget.
            attempts.failures++;
            if (attempts.failures >= properties.maxFailures()) {
                attempts.blockedUntil = now.plus(blockFor(attempts.failures));
            }
        }
        boolean verified = verification.getAsBoolean();
        if (verified) {
            synchronized (attempts) {
                attempts.failures = 0;
                attempts.blockedUntil = Instant.MIN;
            }
        }
        return verified;
    }

    private Duration blockFor(int failures) {
        int doublings = Math.min(failures - properties.maxFailures(), 20);
        Duration block = properties.initialBlock().multipliedBy(1L << doublings);
        return block.compareTo(properties.maxBlock()) > 0 ? properties.maxBlock() : block;
    }

    private static final class Attempts {
        int failures;
        Instant blockedUntil = Instant.MIN;
    }
}
