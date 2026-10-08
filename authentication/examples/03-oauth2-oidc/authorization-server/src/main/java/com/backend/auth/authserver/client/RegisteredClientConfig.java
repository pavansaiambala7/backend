package com.backend.auth.authserver.client;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import com.backend.auth.authserver.AuthServerProperties;

/**
 * The clients this authorization server knows. In production, clients live in a database
 * ({@code JdbcRegisteredClientRepository}) and their secrets come from a secret manager.
 */
@Configuration(proxyBeanMethods = false)
class RegisteredClientConfig {

    static final String ORDERS_READ = "orders.read";

    @Bean
    RegisteredClientRepository registeredClientRepository(AuthServerProperties properties, PasswordEncoder passwordEncoder) {
        return new InMemoryRegisteredClientRepository(
                bffClient(properties, passwordEncoder),
                serviceClient(properties, passwordEncoder));
    }

    /** The client-app module: a confidential web client that logs users in with OpenID Connect. */
    private static RegisteredClient bffClient(AuthServerProperties properties, PasswordEncoder passwordEncoder) {
        AuthServerProperties.BffClient client = properties.bffClient();
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                // Stored hashed, like a password.
                .clientSecret(passwordEncoder.encode(client.clientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // Only the code flow (plus refresh). No implicit, no password grant: Spring Authorization
                // Server does not implement those deprecated grants at all (RFC 9700).
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // Compared with exact string matching: no wildcards, no prefix matching, so a code
                // can never be delivered to a URL the client does not own.
                .redirectUri(client.redirectUri())
                // RP-initiated logout may only send the browser back to this registered URL
                // (otherwise /connect/logout would be an open redirector).
                .postLogoutRedirectUri(client.postLogoutRedirectUri())
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(ORDERS_READ)
                .clientSettings(ClientSettings.builder()
                        // PKCE even though this client has a secret: it binds the code to the browser
                        // session that started the flow, which stops authorization code injection.
                        .requireProofKey(true)
                        // First-party client: no consent screen. Third-party clients should get one.
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(properties.tokens().accessTokenTtl())
                        .authorizationCodeTimeToLive(properties.tokens().authorizationCodeTtl())
                        .refreshTokenTimeToLive(properties.tokens().refreshTokenTtl())
                        // Rotate: every refresh returns a new refresh token and the old one stops working.
                        // (The default, true, would keep one long-lived refresh token for the whole session.)
                        .reuseRefreshTokens(false)
                        .build())
                .build();
    }

    /** A backend job calling the orders API on its own behalf (no user involved). */
    private static RegisteredClient serviceClient(AuthServerProperties properties, PasswordEncoder passwordEncoder) {
        AuthServerProperties.ServiceClient client = properties.serviceClient();
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientSecret(passwordEncoder.encode(client.clientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(ORDERS_READ)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(properties.tokens().accessTokenTtl())
                        .build())
                .build();
    }
}
