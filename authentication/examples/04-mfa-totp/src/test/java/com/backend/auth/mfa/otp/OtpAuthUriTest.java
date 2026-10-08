package com.backend.auth.mfa.otp;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class OtpAuthUriTest {

    @Test
    void buildsTheKeyUriFormatWithPercentEncodedLabel() {
        String uri = OtpAuthUri.totp("Auth Guide Demo", "alice@example.com", "JBSWY3DPEHPK3PXP",
                Totp.authenticatorAppDefaults());

        assertThat(uri).isEqualTo("otpauth://totp/Auth%20Guide%20Demo:alice%40example.com"
                + "?secret=JBSWY3DPEHPK3PXP&issuer=Auth%20Guide%20Demo&algorithm=SHA1&digits=6&period=30");
    }

    @Test
    void aColonInTheIssuerCannotSplitTheLabel() {
        String uri = OtpAuthUri.totp("Evil:Corp", "bob", "JBSWY3DPEHPK3PXP", Totp.authenticatorAppDefaults());

        assertThat(uri).startsWith("otpauth://totp/Evil%3ACorp:bob?");
    }
}
