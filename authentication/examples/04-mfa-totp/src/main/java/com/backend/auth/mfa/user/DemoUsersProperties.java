package com.backend.auth.mfa.user;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

/** DEMO ONLY: password users from configuration. A real application reads them from its user store. */
@Validated
@ConfigurationProperties("demo")
public record DemoUsersProperties(List<@Valid DemoUser> users) {

    public DemoUsersProperties {
        users = users == null ? List.of() : users;
    }

    /** @param passwordHash self-describing hash such as {@code {argon2}$argon2id$v=19$m=19456,t=2,p=1$...} */
    public record DemoUser(@NotBlank String username, @NotBlank String passwordHash) {
    }
}
