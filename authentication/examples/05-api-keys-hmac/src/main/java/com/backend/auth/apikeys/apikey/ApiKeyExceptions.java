package com.backend.auth.apikeys.apikey;

import java.util.UUID;

/** Domain errors of key management; the admin controller maps them to RFC 9457 problem responses. */
public final class ApiKeyExceptions {

    private ApiKeyExceptions() {
    }

    /** Also thrown for another owner's key, so tenants cannot probe which key ids exist. */
    public static final class KeyNotFound extends RuntimeException {
        public KeyNotFound(UUID id) {
            super("No API key " + id);
        }
    }

    public static final class InvalidKeyRequest extends RuntimeException {
        public InvalidKeyRequest(String message) {
            super(message);
        }
    }

    public static final class KeyNotRotatable extends RuntimeException {
        public KeyNotRotatable(String message) {
            super(message);
        }
    }
}
