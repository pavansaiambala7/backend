package com.backend.auth.authserver.user;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * <strong>DEMO ONLY:</strong> two users whose passwords are in the source code so the example runs
 * without setup. They are hashed with Argon2id at startup, so the user store itself never holds plain
 * text. A real authorization server keeps users in a database (see example 01) or federates to a
 * corporate IdP, and adds MFA (example 04).
 */
@Configuration(proxyBeanMethods = false)
class DemoUserConfig {

    private static final List<DemoUser> DEMO_USERS = List.of(
            new DemoUser("alice", "Alice Anderson", "alice-demo-password"),
            new DemoUser("bob", "Bob Brown", "bob-demo-password"));

    @Bean
    InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
        List<UserDetails> users = DEMO_USERS.stream()
                .map(user -> User.withUsername(user.username())
                        .password(passwordEncoder.encode(user.demoPassword()))
                        .roles("USER")
                        .build())
                .toList();
        return new InMemoryUserDetailsManager(users);
    }

    @Bean
    UserProfiles userProfiles() {
        return new UserProfiles(DEMO_USERS.stream()
                .map(user -> new UserProfile(user.username(), user.fullName()))
                .toList());
    }

    private record DemoUser(String username, String fullName, String demoPassword) {
    }
}
