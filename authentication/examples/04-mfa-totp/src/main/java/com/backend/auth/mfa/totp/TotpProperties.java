package com.backend.auth.mfa.totp;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/**
 * @param issuer            service name shown in the authenticator app next to the account
 * @param allowedDriftSteps time steps accepted on either side of "now" (1 = codes from 30 s ago and 30 s ahead)
 */
@Validated
@ConfigurationProperties("mfa.totp")
public record TotpProperties(@NotBlank String issuer, @Min(0) @Max(2) int allowedDriftSteps) {
}
