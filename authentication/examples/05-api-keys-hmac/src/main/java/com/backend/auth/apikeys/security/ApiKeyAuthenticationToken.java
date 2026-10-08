package com.backend.auth.apikeys.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Before authentication it carries the presented key as credentials and no principal; afterwards it carries
 * an {@link ApiKeyPrincipal} and the key's scopes as authorities, and the key itself is gone.
 */
public final class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

    private final ApiKeyPrincipal principal;
    private final String presentedKey;

    private ApiKeyAuthenticationToken(ApiKeyPrincipal principal, String presentedKey,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.presentedKey = presentedKey;
        setAuthenticated(principal != null);
    }

    public static ApiKeyAuthenticationToken unauthenticated(String presentedKey) {
        return new ApiKeyAuthenticationToken(null, presentedKey, List.of());
    }

    public static ApiKeyAuthenticationToken authenticated(ApiKeyPrincipal principal,
            Collection<? extends GrantedAuthority> authorities) {
        return new ApiKeyAuthenticationToken(principal, null, authorities);
    }

    @Override
    public String getCredentials() {
        return presentedKey;
    }

    @Override
    public ApiKeyPrincipal getPrincipal() {
        return principal;
    }

    /** The default toString lists principal and details; make sure no future change can print the key. */
    @Override
    public String toString() {
        return "ApiKeyAuthenticationToken[principal=" + principal + ", authorities=" + getAuthorities() + "]";
    }
}
