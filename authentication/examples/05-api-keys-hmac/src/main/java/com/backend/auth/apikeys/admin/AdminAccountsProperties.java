package com.backend.auth.apikeys.admin;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

/**
 * DEMO ONLY: the people who may manage API keys, from configuration. In a real product this is your
 * dashboard login (session + MFA, or OpenID Connect), not a list in a YAML file.
 */
@Validated
@ConfigurationProperties("admin")
public record AdminAccountsProperties(@NotEmpty List<@Valid AdminAccount> accounts) {

    /**
     * @param owner        the account (tenant) whose keys this administrator manages
     * @param passwordHash self-describing hash, e.g. {@code {argon2}$argon2id$v=19$m=19456,t=2,p=1$...}
     */
    public record AdminAccount(@NotBlank String username, @NotBlank String owner, @NotBlank String passwordHash) {
    }
}
