package com.backend.auth.apikeys.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HMAC-SHA256 (RFC 2104) and SHA-256 helpers. {@link Mac} is not thread-safe, so each call gets its own. */
public final class HmacSha256 {

    public static final String ALGORITHM = "HmacSHA256";
    public static final int LENGTH_BYTES = 32;

    private HmacSha256() {
    }

    public static byte[] mac(byte[] key, byte[] data) {
        return mac(new SecretKeySpec(key, ALGORITHM), data);
    }

    public static byte[] mac(SecretKeySpec key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return mac.doFinal(data);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is required by every Java SE implementation", e);
        }
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is required by every Java SE implementation", e);
        }
    }
}
