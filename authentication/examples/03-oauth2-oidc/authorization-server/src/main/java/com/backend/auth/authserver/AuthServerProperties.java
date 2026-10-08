package com.backend.auth.authserver;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings of the authorization server, bound from {@code authserver.*} in application.yml.
 *
 * @param issuer        the issuer identifier: the exact {@code iss} value in every token and in the
 *                      discovery document; clients and resource servers compare against it
 * @param bffClient     the confidential web client (the client-app module)
 * @param serviceClient a machine client using the client credentials grant
 * @param tokens        token lifetimes
 * @param apis          resource servers (APIs) and the scopes that belong to them; used to set {@code aud}
 */
@ConfigurationProperties("authserver")
public record AuthServerProperties(
        String issuer,
        BffClient bffClient,
        ServiceClient serviceClient,
        Tokens tokens,
        List<ApiResource> apis) {

    public record BffClient(String clientId, String clientSecret, String redirectUri, String postLogoutRedirectUri) {
    }

    public record ServiceClient(String clientId, String clientSecret) {
    }

    public record Tokens(Duration accessTokenTtl, Duration refreshTokenTtl, Duration authorizationCodeTtl) {
    }

    /** An API that accepts access tokens, identified by the audience value it checks. */
    public record ApiResource(String audience, Set<String> scopes) {
    }
}
