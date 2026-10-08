package com.backend.auth.apikeys.security;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.backend.auth.apikeys.apikey.ApiKey;
import com.backend.auth.apikeys.apikey.ApiKeyVerifier;
import com.backend.auth.apikeys.apikey.ApiKeyVerifier.Verification;

/**
 * Turns a presented key into an authenticated principal whose authorities are the key's scopes
 * ({@code SCOPE_orders:read}, the same convention Spring Security uses for OAuth 2 access tokens).
 */
public final class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    /** One message for unknown, malformed, revoked and expired keys: the caller learns nothing about key state. */
    static final String INVALID_KEY = "The API key is invalid, expired or revoked.";

    private final ApiKeyVerifier verifier;

    public ApiKeyAuthenticationProvider(ApiKeyVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        String presented = ((ApiKeyAuthenticationToken) authentication).getCredentials();
        Verification verification = verifier.verify(presented);
        if (!verification.valid()) {
            throw new BadCredentialsException(INVALID_KEY);   // the real reason is logged by the verifier
        }
        ApiKey key = verification.key();
        List<SimpleGrantedAuthority> authorities = key.scopes().stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .toList();
        return ApiKeyAuthenticationToken.authenticated(new ApiKeyPrincipal(key.id(), key.owner(), key.prefix()), authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
