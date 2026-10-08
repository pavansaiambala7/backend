package com.backend.auth.apikeys.apikey;

import java.time.Duration;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/**
 * @param environment          {@code live} or {@code test}: decides the key prefix
 * @param pepper               base64 HMAC key (at least 32 bytes) used to hash keys at rest; from a secret manager in production
 * @param scopes               every scope a key may be granted; anything else is refused at creation
 * @param defaultLifetime      expiry when the creator does not choose one
 * @param maxLifetime          no key lives longer, so forgotten keys die on their own
 * @param rotationOverlap      how long the old key keeps working after a rotation
 * @param lastUsedGranularity  {@code last_used_at} is written at most this often per key (one write per request would not scale)
 */
@Validated
@ConfigurationProperties("api-keys")
public record ApiKeyProperties(
        @NotNull KeyEnvironment environment,
        @NotBlank String pepper,
        @NotEmpty Set<@Pattern(regexp = "[a-z]+:[a-z]+") String> scopes,
        @DefaultValue("90d") Duration defaultLifetime,
        @DefaultValue("365d") Duration maxLifetime,
        @DefaultValue("24h") Duration rotationOverlap,
        @DefaultValue("1m") Duration lastUsedGranularity) {
}
