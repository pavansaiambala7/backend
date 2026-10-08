package com.backend.auth.mfa.otp;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HOTP, RFC 4226: {@code Truncate(HMAC(K, C)) mod 10^digits}. TOTP (RFC 6238) is this function with a
 * counter derived from the clock, see {@link Totp}.
 */
public final class Hotp {

    private static final int[] POWERS_OF_TEN = {1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000};

    private Hotp() {
    }

    /**
     * @param key       the shared secret (raw bytes, not Base32)
     * @param counter   the moving factor: an event counter for HOTP, the time step for TOTP
     * @param digits    6 to 8
     * @param algorithm the HMAC function
     * @return the code, left-padded with zeros to {@code digits} characters
     */
    public static String generate(byte[] key, long counter, int digits, HmacAlgorithm algorithm) {
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("digits must be between 6 and 8");
        }
        byte[] hash = hmac(key, ByteBuffer.allocate(Long.BYTES).putLong(counter).array(), algorithm);

        // Dynamic truncation (RFC 4226, section 5.3): the low 4 bits of the last byte pick an offset,
        // and the 31 bits starting there (top bit masked off to avoid signed/unsigned ambiguity) are the value.
        int offset = hash[hash.length - 1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

        int otp = binary % POWERS_OF_TEN[digits];
        return String.format("%0" + digits + "d", otp);
    }

    private static byte[] hmac(byte[] key, byte[] message, HmacAlgorithm algorithm) {
        try {
            Mac mac = Mac.getInstance(algorithm.jcaName());
            mac.init(new SecretKeySpec(key, algorithm.jcaName()));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(algorithm.jcaName() + " is not available", e);
        }
    }
}
