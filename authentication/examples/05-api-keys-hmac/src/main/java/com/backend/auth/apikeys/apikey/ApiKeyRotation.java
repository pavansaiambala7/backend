package com.backend.auth.apikeys.apikey;

/** Result of a rotation: the new key (shown once) and the old key, now expiring at the end of the overlap. */
public record ApiKeyRotation(IssuedApiKey replacement, ApiKey previous) {
}
