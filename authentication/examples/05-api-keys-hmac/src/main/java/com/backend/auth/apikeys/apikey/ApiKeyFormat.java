package com.backend.auth.apikeys.apikey;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.zip.CRC32;

/**
 * Generates and recognizes API keys of the form
 *
 * <pre>
 * ak_live_AyheSk0UkuY4B2okpAeLPXi3SHJrYP4k8hnFelGywjc1MPUZd
 * \______/\_________________________________________/\____/
 *  prefix      secret: 32 random bytes as 43 base62 chars     checksum: CRC32 in 6 base62 chars
 * </pre>
 *
 * <ul>
 * <li>The prefix names the key type and environment, so humans and secret scanners recognize a leaked key.</li>
 * <li>Base62 has no {@code -}, {@code _} or {@code =}: a double-click selects the whole key.</li>
 * <li>The checksum lets the server reject typos and random strings without a database query.</li>
 * <li>The first {@value #LOOKUP_CHARS} secret characters double as a lookup id that is stored and displayed
 *     (see {@link #lookupPrefix}). That leaves 35 base62 characters, about 208 bits, actually secret:
 *     far above the 128-bit minimum.</li>
 * </ul>
 */
public final class ApiKeyFormat {

    static final int SECRET_BYTES = 32;      // 256 bits from a CSPRNG
    static final int SECRET_CHARS = 43;      // 62^43 > 2^256, so 43 base62 digits hold any 32-byte value
    static final int CHECKSUM_CHARS = 6;     // 62^6 > 2^32 holds any CRC32 value
    static final int LOOKUP_CHARS = 8;

    private static final String BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final BigInteger SIXTY_TWO = BigInteger.valueOf(62);

    private final String prefix;
    private final SecureRandom random;

    public ApiKeyFormat(KeyEnvironment environment, SecureRandom random) {
        this.prefix = environment.prefix();
        this.random = random;
    }

    public String generate() {
        byte[] secret = new byte[SECRET_BYTES];
        random.nextBytes(secret);
        String body = prefix + base62(new BigInteger(1, secret), SECRET_CHARS);
        return body + checksum(body);
    }

    /**
     * The part of the key that is stored in clear for lookup and display (for example {@code ak_live_7Fq2Lx9P}),
     * or empty when the candidate is not a well-formed key for this environment.
     */
    public Optional<String> lookupPrefix(String candidate) {
        if (!isWellFormed(candidate)) {
            return Optional.empty();
        }
        return Optional.of(candidate.substring(0, prefix.length() + LOOKUP_CHARS));
    }

    public int keyLength() {
        return prefix.length() + SECRET_CHARS + CHECKSUM_CHARS;
    }

    boolean isWellFormed(String candidate) {
        if (candidate == null || candidate.length() != keyLength() || !candidate.startsWith(prefix)) {
            return false;
        }
        for (int i = prefix.length(); i < candidate.length(); i++) {
            if (BASE62.indexOf(candidate.charAt(i)) < 0) {
                return false;
            }
        }
        String body = candidate.substring(0, candidate.length() - CHECKSUM_CHARS);
        // The checksum is derived from public data and protects nothing, so a plain equals is fine here.
        return checksum(body).equals(candidate.substring(body.length()));
    }

    private static String checksum(String body) {
        CRC32 crc = new CRC32();
        crc.update(body.getBytes(StandardCharsets.US_ASCII));
        return base62(BigInteger.valueOf(crc.getValue()), CHECKSUM_CHARS);
    }

    /** Fixed-width base62, most significant digit first, left-padded with '0'. */
    private static String base62(BigInteger value, int width) {
        char[] digits = new char[width];
        BigInteger remaining = value;
        for (int i = width - 1; i >= 0; i--) {
            BigInteger[] quotientAndRemainder = remaining.divideAndRemainder(SIXTY_TWO);
            digits[i] = BASE62.charAt(quotientAndRemainder[1].intValue());
            remaining = quotientAndRemainder[0];
        }
        return new String(digits);
    }
}
