package com.backend.auth.apikeys.apikey;

import java.nio.charset.StandardCharsets;

import javax.crypto.spec.SecretKeySpec;

import com.backend.auth.apikeys.crypto.HmacSha256;

/**
 * Hashes API keys for storage as HMAC-SHA256(pepper, key).
 *
 * <p>A fast keyed hash is the right tool here, unlike for passwords: a 256-bit random key cannot be guessed
 * however fast the hash is, and keys are checked on every request, so Argon2id would only add latency and a
 * denial-of-service lever. The pepper lives outside the database (secret manager or KMS in production), so a
 * stolen {@code api_key} table cannot even be used to test candidate keys.
 */
public final class ApiKeyHasher {

    static final int MIN_PEPPER_BYTES = 32;

    private final SecretKeySpec pepper;

    public ApiKeyHasher(byte[] pepper) {
        if (pepper.length < MIN_PEPPER_BYTES) {
            throw new IllegalArgumentException("The API key pepper must be at least " + MIN_PEPPER_BYTES + " bytes");
        }
        this.pepper = new SecretKeySpec(pepper, HmacSha256.ALGORITHM);
    }

    public byte[] hash(String apiKey) {
        return HmacSha256.mac(pepper, apiKey.getBytes(StandardCharsets.US_ASCII));
    }
}
