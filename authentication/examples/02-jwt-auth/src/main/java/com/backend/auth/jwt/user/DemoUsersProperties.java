package com.backend.auth.jwt.user;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

/** DEMO ONLY: users from configuration. A real service reads them from its user store or IdP. */
@Validated
@ConfigurationProperties("auth")
public record DemoUsersProperties(@NotEmpty List<@Valid DemoUser> users) {

    /**
     * @param passwordHash self-describing hash such as {@code {argon2}$argon2id$v=19$m=19456,t=2,p=1$...}
     * @param scopes       what this user's access tokens may do, e.g. {@code orders:read}
     */
    public record DemoUser(@NotBlank String username, @NotBlank String passwordHash, List<@NotBlank String> scopes) {
    }
}
