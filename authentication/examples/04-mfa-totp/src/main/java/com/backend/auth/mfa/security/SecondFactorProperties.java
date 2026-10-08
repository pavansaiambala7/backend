package com.backend.auth.mfa.security;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

/**
 * @param timeout      how long after the password step the second factor (or enrollment) may still be completed;
 *                     a half-signed-in session should not wait indefinitely for someone to guess codes
 * @param maxFailures  consecutive wrong codes per account before attempts are blocked
 * @param initialBlock first block; it doubles with every further failure
 * @param maxBlock     upper bound for a single block
 */
@Validated
@ConfigurationProperties("mfa.second-factor")
public record SecondFactorProperties(
        @NotNull Duration timeout,
        @Min(1) @Max(100) int maxFailures,
        @NotNull Duration initialBlock,
        @NotNull Duration maxBlock) {
}
