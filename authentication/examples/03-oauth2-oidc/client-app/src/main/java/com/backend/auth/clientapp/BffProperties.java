package com.backend.auth.clientapp;

import java.time.Duration;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Bound from {@code bff.*} in application.yml.
 *
 * @param registrationId the local name of the OpenID Provider registration (used in callback URLs)
 * @param provider       the OpenID Provider's identifier and endpoints
 * @param client         this application's client registration at the provider
 * @param ordersApi      the resource server this BFF calls for the user
 */
@ConfigurationProperties("bff")
public record BffProperties(String registrationId, Provider provider, Client client, OrdersApi ordersApi) {

    /** Values copied from the provider's /.well-known/openid-configuration. */
    public record Provider(
            String issuer,
            String authorizationUri,
            String tokenUri,
            String jwkSetUri,
            String userInfoUri,
            String endSessionUri) {
    }

    public record Client(String clientId, String clientSecret, Set<String> scopes) {
    }

    public record OrdersApi(String baseUrl, Duration connectTimeout, Duration readTimeout) {
    }
}
