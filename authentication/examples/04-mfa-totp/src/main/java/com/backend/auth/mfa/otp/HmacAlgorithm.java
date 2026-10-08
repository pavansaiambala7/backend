package com.backend.auth.mfa.otp;

/**
 * The HMAC functions RFC 6238 allows. Authenticator apps overwhelmingly support only SHA1 (many ignore the
 * {@code algorithm} parameter), so the application uses SHA1; SHA256 and SHA512 exist here to run every
 * RFC 6238 test vector. HMAC-SHA-1 is still sound for OTPs: HMAC does not rely on SHA-1's collision
 * resistance.
 */
public enum HmacAlgorithm {

    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512");

    private final String jcaName;

    HmacAlgorithm(String jcaName) {
        this.jcaName = jcaName;
    }

    /** The name {@link javax.crypto.Mac#getInstance(String)} expects. */
    public String jcaName() {
        return jcaName;
    }
}
