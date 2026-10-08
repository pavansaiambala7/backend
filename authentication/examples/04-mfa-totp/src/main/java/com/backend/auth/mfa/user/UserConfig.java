package com.backend.auth.mfa.user;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration(proxyBeanMethods = false)
class UserConfig {

    private static final String DEFAULT_ENCODING_ID = "argon2";

    /**
     * Argon2id with the OWASP minimum (16-byte salt, 32-byte hash, p=1, m=19456 KiB, t=2) for passwords and
     * recovery codes; bcrypt hashes from a legacy system still verify and are re-hashed at the next login.
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = Map.of(
                DEFAULT_ENCODING_ID, new Argon2PasswordEncoder(16, 32, 1, 19_456, 2),
                "bcrypt", new BCryptPasswordEncoder(12));
        return new DelegatingPasswordEncoder(DEFAULT_ENCODING_ID, encoders);
    }

    /**
     * DEMO ONLY: users live in memory (the MFA state is in the database). {@link InMemoryUserDetailsManager} is also
     * a {@code UserDetailsPasswordService}, so outdated password hashes are upgraded at login.
     */
    @Bean
    InMemoryUserDetailsManager userDetailsService(DemoUsersProperties properties) {
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        properties.users().forEach(user -> users.createUser(User.withUsername(user.username())
                .password(user.passwordHash())
                .roles("USER")
                .build()));
        return users;
    }
}
