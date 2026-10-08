package com.backend.auth.resourceserver.security;

import java.util.List;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;

/**
 * The claim checks every access token must pass after its signature has been verified.
 * Shared by the production decoder and the tests, so the tests prove what production enforces.
 */
public final class AccessTokenValidators {

    private AccessTokenValidators() {
    }

    public static OAuth2TokenValidator<Jwt> forApi(ResourceServerProperties properties) {
        // createDefaultWithValidators adds the defaults: exp and nbf (60 s clock skew) and a "typ"
        // header check (JWT or absent).
        return JwtValidators.createDefaultWithValidators(List.of(
                // A token from any other issuer, even with a valid signature from a key we somehow
                // trust, is not ours to accept.
                new JwtIssuerValidator(properties.issuer()),
                // A token issued for another API, or an ID token (aud = client ID), is refused here.
                // Without this check any token from the same issuer would work at every API.
                new JwtAudienceValidator(properties.audience())));
    }
}
