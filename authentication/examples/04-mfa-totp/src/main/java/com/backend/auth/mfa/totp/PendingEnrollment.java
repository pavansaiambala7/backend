package com.backend.auth.mfa.totp;

/**
 * What the user needs to add the account to an authenticator app.
 *
 * @param secret     Base32 secret without padding, for typing it in by hand
 * @param otpauthUri the same secret as an {@code otpauth://} URI, which is what a QR code would contain
 */
public record PendingEnrollment(String secret, String otpauthUri) {
}
