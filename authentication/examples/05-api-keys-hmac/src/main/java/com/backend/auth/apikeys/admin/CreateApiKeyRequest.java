package com.backend.auth.apikeys.admin;

import java.util.Set;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

/**
 * @param name          what the key is for, e.g. "CI deploy key"; shown in listings
 * @param scopes        least privilege: only what this integration needs
 * @param expiresInDays optional; the configured default (90 days) when absent, never above the configured maximum
 */
public record CreateApiKeyRequest(
        @NotBlank @Size(max = 100) String name,
        @NotEmpty @Size(max = 20) Set<@NotBlank String> scopes,
        @Min(1) @Max(3650) Integer expiresInDays) {
}
