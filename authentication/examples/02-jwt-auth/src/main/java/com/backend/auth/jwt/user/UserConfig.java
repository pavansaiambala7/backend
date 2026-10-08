package com.backend.auth.jwt.user;

import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration(proxyBeanMethods = false)
class UserConfig {

    private static final String DEFAULT_ENCODING_ID = "argon2";

    /**
     * New hashes are Argon2id with the OWASP minimum (16-byte salt, 32-byte hash, p=1, m=19456 KiB,
     * t=2); bcrypt hashes from a legacy system still verify and are re-hashed at the next login.
     * {@code PasswordEncoderFactories.createDelegatingPasswordEncoder()} would default to bcrypt.
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = Map.of(
                DEFAULT_ENCODING_ID, new Argon2PasswordEncoder(16, 32, 1, 19_456, 2),
                "bcrypt", new BCryptPasswordEncoder(12));
        return new DelegatingPasswordEncoder(DEFAULT_ENCODING_ID, encoders);
    }

    /**
     * Each user's scopes become authorities here; at login they are copied into the access token's
     * {@code scope} claim. {@link InMemoryUserDetailsManager} is also a {@code UserDetailsPasswordService},
     * so hash upgrades at login work out of the box.
     */
    @Bean
    InMemoryUserDetailsManager userDetailsService(DemoUsersProperties properties) {
        List<UserDetails> users = properties.users().stream()
                .map(user -> User.withUsername(user.username())
                        .password(user.passwordHash())
                        .authorities(user.scopes() == null ? new String[0] : user.scopes().toArray(String[]::new))
                        .build())
                .toList();
        return new InMemoryUserDetailsManager(users);
    }
}
