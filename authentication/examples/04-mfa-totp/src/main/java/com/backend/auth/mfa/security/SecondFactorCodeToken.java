package com.backend.auth.mfa.security;

import java.io.Serial;
import java.util.List;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * An unauthenticated request to verify a second-factor code. The username is not taken from the request: it is
 * the user who already passed the password step in this session.
 */
public final class SecondFactorCodeToken extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String username;
    private final SecondFactor factor;
    private @Nullable String code;

    public SecondFactorCodeToken(String username, String code, SecondFactor factor) {
        super(List.of());
        this.username = username;
        this.code = code;
        this.factor = factor;
        setAuthenticated(false);
    }

    public SecondFactor factor() {
        return factor;
    }

    @Override
    public String getPrincipal() {
        return username;
    }

    @Override
    public @Nullable String getCredentials() {
        return code;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        code = null;
    }
}
