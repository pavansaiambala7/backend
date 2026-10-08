package com.backend.auth.jwt.refresh;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * @param cookieName       name of the HttpOnly cookie that carries the refresh token
 * @param cookiePath       the cookie is only sent to paths under this one
 * @param idleTimeout      a refresh token not used for this long expires
 * @param absoluteLifetime a family (one login) expires this long after the login, however active
 */
@Validated
@ConfigurationProperties("auth.refresh-token")
public record RefreshTokenProperties(
        @NotBlank String cookieName,
        @NotBlank String cookiePath,
        @NotNull Duration idleTimeout,
        @NotNull Duration absoluteLifetime) {
}
