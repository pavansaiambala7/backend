package com.backend.auth.mfa.otp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalLong;

/**
 * TOTP, RFC 6238: {@code HOTP(K, T)} with {@code T = floor((now - T0) / period)} and {@code T0} = the Unix epoch.
 *
 * @param algorithm HMAC function
 * @param digits    code length
 * @param period    time step length ("X" in the RFC)
 */
public record Totp(HmacAlgorithm algorithm, int digits, Duration period) {

    /** SHA1, 6 digits, 30 seconds: the only parameters every authenticator app supports. */
    public static Totp authenticatorAppDefaults() {
        return new Totp(HmacAlgorithm.SHA1, 6, Duration.ofSeconds(30));
    }

    public Totp {
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("digits must be between 6 and 8");
        }
        if (period.toSeconds() < 1) {
            throw new IllegalArgumentException("period must be at least one second");
        }
    }

    /** The time step {@code T} that contains {@code instant}. */
    public long timeStep(Instant instant) {
        return Math.floorDiv(instant.getEpochSecond(), period.toSeconds());
    }

    public String codeAt(byte[] key, long timeStep) {
        return Hotp.generate(key, timeStep, digits, algorithm);
    }

    public String codeAt(byte[] key, Instant instant) {
        return codeAt(key, timeStep(instant));
    }

    /**
     * Finds the time step a submitted code belongs to.
     *
     * <p>Accepts the steps {@code now - driftSteps .. now + driftSteps}: the user's clock may be off, and typing
     * takes time. RFC 6238, section 5.2, recommends at most one step of tolerance; every extra step gives an
     * attacker more valid codes to hit. This method does <em>not</em> prevent replay: the caller must accept a
     * step only if it is later than the last one accepted for this secret, and record it atomically.
     *
     * @return the matched step, or empty if the code is malformed, wrong or outside the window
     */
    public OptionalLong matchingStep(byte[] key, String code, Instant now, int driftSteps) {
        if (code == null || code.length() != digits || !code.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return OptionalLong.empty();
        }
        byte[] submitted = code.getBytes(StandardCharsets.US_ASCII);
        long current = timeStep(now);
        long matched = Long.MIN_VALUE;
        // Check every step in the window (no early exit) and compare in constant time, so response timing
        // reveals nothing about how close a guess was or which step matched.
        for (long step = current - driftSteps; step <= current + driftSteps; step++) {
            byte[] expected = codeAt(key, step).getBytes(StandardCharsets.US_ASCII);
            if (MessageDigest.isEqual(expected, submitted)) {
                matched = Math.max(matched, step);
            }
        }
        return matched == Long.MIN_VALUE ? OptionalLong.empty() : OptionalLong.of(matched);
    }
}
