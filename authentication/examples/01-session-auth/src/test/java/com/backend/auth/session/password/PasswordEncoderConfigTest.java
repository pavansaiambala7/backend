package com.backend.auth.session.password;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class PasswordEncoderConfigTest {

    private static final String PASSWORD = "plaid otter sings at dawn";

    private final PasswordEncoder encoder = new PasswordEncoderConfig().passwordEncoder();

    @Test
    void encodesNewPasswordsWithArgon2idAndARandomSalt() {
        String first = encoder.encode(PASSWORD);
        String second = encoder.encode(PASSWORD);

        assertThat(first).startsWith("{argon2}$argon2id$v=19$m=19456,t=2,p=1$");
        assertThat(first).isNotEqualTo(second);   // unique salt per hash
        assertThat(encoder.matches(PASSWORD, first)).isTrue();
        assertThat(encoder.matches("plaid otter sings at dusk", first)).isFalse();
        assertThat(encoder.upgradeEncoding(first)).isFalse();
    }

    @Test
    void verifiesLegacyHashesAndFlagsThemForUpgrade() {
        String bcrypt = "{bcrypt}" + new BCryptPasswordEncoder(10).encode(PASSWORD);
        // An older, weaker Argon2id parameter set (4 MiB, t=3), like Spring Security 5.2's defaults.
        String weakArgon2 = "{argon2}" + new Argon2PasswordEncoder(16, 32, 1, 4096, 3).encode(PASSWORD);

        assertThat(encoder.matches(PASSWORD, bcrypt)).isTrue();
        assertThat(encoder.upgradeEncoding(bcrypt)).isTrue();
        assertThat(encoder.matches(PASSWORD, weakArgon2)).isTrue();
        assertThat(encoder.upgradeEncoding(weakArgon2)).isTrue();   // m=4096 KiB is below the configured 19456
    }

    @Test
    void normalizesUnicodeSoEquivalentInputsMatch() {
        String composed = "café on the corner at noon";      // é as one code point
        String decomposed = "café on the corner at noon";   // e + combining acute accent

        assertThat(encoder.matches(decomposed, encoder.encode(composed))).isTrue();
    }
}
