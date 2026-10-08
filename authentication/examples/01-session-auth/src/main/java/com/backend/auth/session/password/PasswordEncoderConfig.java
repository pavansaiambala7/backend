package com.backend.auth.session.password;

import java.text.Normalizer;
import java.util.HashMap;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

@Configuration(proxyBeanMethods = false)
class PasswordEncoderConfig {

    static final String DEFAULT_ENCODING_ID = "argon2";

    /**
     * New hashes are Argon2id; older formats keep verifying and are re-hashed at the next login.
     * {@code PasswordEncoderFactories.createDelegatingPasswordEncoder()} would default to bcrypt,
     * which is why the map is built by hand.
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        // Argon2id with the OWASP minimum: 16-byte salt, 32-byte hash, p=1, m=19456 KiB (19 MiB), t=2.
        // Spring's defaultsForSpringSecurity_v5_8() uses 16 MiB, slightly below that floor.
        // Argon2PasswordEncoder.upgradeEncoding() also flags stored Argon2 hashes with weaker
        // parameters, so raising these numbers later upgrades existing users automatically.
        encoders.put(DEFAULT_ENCODING_ID, new Argon2PasswordEncoder(16, 32, 1, 19_456, 2));
        // Legacy formats: accepted for verification only, upgraded to Argon2id on successful login.
        encoders.put("bcrypt", new BCryptPasswordEncoder(12));
        encoders.put("pbkdf2@SpringSecurity_v5_8", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());

        return new NfcPasswordEncoder(new DelegatingPasswordEncoder(DEFAULT_ENCODING_ID, encoders));
    }

    /**
     * Applies Unicode NFC normalization before hashing and verifying, as NIST SP 800-63B-4
     * recommends: the same visible password typed on two keyboards can produce different code
     * point sequences ("é" as one code point or as "e" + combining accent).
     */
    static final class NfcPasswordEncoder implements PasswordEncoder {

        private final PasswordEncoder delegate;

        NfcPasswordEncoder(PasswordEncoder delegate) {
            this.delegate = delegate;
        }

        @Override
        public @Nullable String encode(@Nullable CharSequence rawPassword) {
            return delegate.encode(nfc(rawPassword));
        }

        @Override
        public boolean matches(@Nullable CharSequence rawPassword, @Nullable String encodedPassword) {
            return delegate.matches(nfc(rawPassword), encodedPassword);
        }

        @Override
        public boolean upgradeEncoding(@Nullable String encodedPassword) {
            return delegate.upgradeEncoding(encodedPassword);
        }

        private static @Nullable String nfc(@Nullable CharSequence raw) {
            return raw == null ? null : Normalizer.normalize(raw, Normalizer.Form.NFC);
        }
    }
}
