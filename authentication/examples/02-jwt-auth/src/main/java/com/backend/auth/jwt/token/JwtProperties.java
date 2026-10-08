package com.backend.auth.jwt.token;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Settings shared by the issuer (login, refresh) and the verifier (resource endpoints).
 *
 * @param issuer         {@code iss}: who issued the token, compared exactly by verifiers
 * @param audience       {@code aud}: the API the token is for; another API must refuse it
 * @param clientId       {@code client_id} (RFC 9068): the client the token was issued to
 * @param accessTokenTtl access-token lifetime; keep it short (5-15 min) because it cannot be revoked
 * @param clockSkew      tolerance for {@code exp}, {@code nbf} and {@code iat} between hosts
 */
@Validated
@ConfigurationProperties("auth.jwt")
public record JwtProperties(
        @NotBlank String issuer,
        @NotBlank String audience,
        @NotBlank String clientId,
        @NotNull Duration accessTokenTtl,
        @NotNull Duration clockSkew) {
}
