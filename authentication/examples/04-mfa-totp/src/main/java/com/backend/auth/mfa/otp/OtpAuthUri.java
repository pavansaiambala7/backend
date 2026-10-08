package com.backend.auth.mfa.otp;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Builds the {@code otpauth://} URI that authenticator apps import, usually from a QR code. The format is the
 * de facto "Key Uri Format" published with Google Authenticator, not an RFC.
 *
 * <pre>otpauth://totp/Issuer:account?secret=BASE32&amp;issuer=Issuer&amp;algorithm=SHA1&amp;digits=6&amp;period=30</pre>
 */
public final class OtpAuthUri {

    private OtpAuthUri() {
    }

    /**
     * @param issuer       service name shown in the app; repeated as a parameter because some apps only read one
     * @param accountName  the user's login name, shown under the issuer
     * @param base32Secret the secret, Base32 without padding
     */
    public static String totp(String issuer, String accountName, String base32Secret, Totp totp) {
        return "otpauth://totp/" + encode(issuer) + ":" + encode(accountName)
                + "?secret=" + base32Secret
                + "&issuer=" + encode(issuer)
                + "&algorithm=" + totp.algorithm().name()
                + "&digits=" + totp.digits()
                + "&period=" + totp.period().toSeconds();
    }

    /** Percent-encoding with {@code %20} for spaces: some apps show a literal {@code +} otherwise. */
    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
