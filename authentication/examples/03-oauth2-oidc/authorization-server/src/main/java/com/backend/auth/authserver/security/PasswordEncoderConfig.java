package com.backend.auth.authserver.security;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Hashes user passwords and client secrets. Spring Authorization Server picks up this bean to verify
 * client secrets at the token endpoint, so neither ever exists in plain text in the user or client store.
 */
@Configuration(proxyBeanMethods = false)
class PasswordEncoderConfig {

    private static final String DEFAULT_ENCODING_ID = "argon2";

    @Bean
    PasswordEncoder passwordEncoder() {
        return new DelegatingPasswordEncoder(DEFAULT_ENCODING_ID, Map.of(
                // Argon2id at the OWASP minimum: 16-byte salt, 32-byte hash, p=1, m=19 MiB, t=2.
                DEFAULT_ENCODING_ID, new Argon2PasswordEncoder(16, 32, 1, 19_456, 2),
                // Legacy hashes still verify and are re-hashed with Argon2id at the next login
                // (InMemoryUserDetailsManager implements UserDetailsPasswordService).
                "bcrypt", new BCryptPasswordEncoder(12)));
    }
}
