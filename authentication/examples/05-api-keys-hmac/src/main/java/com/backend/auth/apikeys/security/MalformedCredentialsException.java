package com.backend.auth.apikeys.security;

import org.springframework.security.core.AuthenticationException;

/** The request itself is wrong (two keys, broken header): RFC 6750 {@code invalid_request}, answered with 400. */
public class MalformedCredentialsException extends AuthenticationException {

    public MalformedCredentialsException(String message) {
        super(message);
    }
}
