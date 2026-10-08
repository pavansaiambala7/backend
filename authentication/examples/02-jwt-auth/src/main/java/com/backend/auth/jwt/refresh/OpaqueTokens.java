package com.backend.auth.jwt.refresh;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

/** Generates and hashes opaque refresh tokens. */
final class OpaqueTokens {

    private static final int TOKEN_BYTES = 32;   // 256 bits from a CSPRNG: unguessable
    private static final SecureRandom RANDOM = new SecureRandom();
    // 32 bytes in unpadded Base64URL are exactly 43 characters.
    private static final Pattern WELL_FORMED = Pattern.compile("[A-Za-z0-9_-]{43}");

    private OpaqueTokens() {
    }

    static String generate() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** What the database stores and looks up: SHA-256 of the token, hex-encoded. */
    static String sha256Hex(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java platform", e);
        }
    }

    /** Cheap syntax check so arbitrary cookie values never reach the database. */
    static boolean isWellFormed(String token) {
        return token != null && WELL_FORMED.matcher(token).matches();
    }
}
