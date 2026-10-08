package com.backend.auth.apikeys.admin;

/** @param previous the old key, still valid until {@code previous.expiresAt} so clients can switch without downtime */
public record RotatedApiKey(CreatedApiKey replacement, ApiKeyView previous) {
}
