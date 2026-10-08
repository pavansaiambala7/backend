package com.backend.auth.mfa.totp;

import java.time.Instant;

import org.jspecify.annotations.Nullable;

/**
 * A user's TOTP authenticator as stored.
 *
 * @param encryptedSecret  AES-GCM ciphertext of the secret, see {@code SecretEncryptor}
 * @param confirmedAt      when the user proved the app works; {@code null} while enrollment is pending
 * @param lastUsedTimeStep the last time step accepted; only later steps are accepted (replay protection)
 */
public record TotpCredential(String username,
                             String encryptedSecret,
                             @Nullable Instant confirmedAt,
                             @Nullable Long lastUsedTimeStep) {

    /** Pending enrollments never count as a second factor. */
    public boolean active() {
        return confirmedAt != null;
    }

    /**
     * Associated data for the secret's AES-GCM encryption: binds each ciphertext to its owner. (Production systems
     * should use an immutable user ID here; usernames can change.)
     */
    static String associatedData(String username) {
        return "totp-secret:" + username;
    }
}
