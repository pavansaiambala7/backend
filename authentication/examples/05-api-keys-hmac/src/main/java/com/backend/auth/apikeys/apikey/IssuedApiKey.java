package com.backend.auth.apikeys.apikey;

/**
 * A freshly created key: the only moment the full secret exists outside the client. It is returned to the
 * creator once and then forgotten; the database only ever sees its hash.
 */
public record IssuedApiKey(String secret, ApiKey key) {

    /** Records print every component by default; a logged IssuedApiKey must not leak the secret. */
    @Override
    public String toString() {
        return "IssuedApiKey[secret=<redacted>, key=" + key + "]";
    }
}
