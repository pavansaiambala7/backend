package com.backend.auth.jwt.security;

import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotNull;

/** @param allowedOrigins exact origins (scheme://host[:port]) whose pages may call {@code /auth/**} */
@Validated
@ConfigurationProperties("auth.csrf")
public record CsrfProperties(@NotNull Set<String> allowedOrigins) {
}
