package com.backend.auth.clientapp.security;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import com.backend.auth.clientapp.BffProperties;

/**
 * The registration of this app at the authorization server.
 *
 * <p>Built in code rather than with {@code spring.security.oauth2.client.provider.*.issuer-uri} for two
 * reasons: issuer-uri makes Spring fetch the discovery document at startup (so the BFF could not start
 * before the authorization server, and tests would need one running), and Boot's properties cannot set
 * {@code requireProofKey}. The values are the ones the discovery document publishes.
 */
@Configuration(proxyBeanMethods = false)
class OidcClientRegistrationConfig {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository(BffProperties properties) {
        return new InMemoryClientRegistrationRepository(authorizationServer(properties));
    }

    private static ClientRegistration authorizationServer(BffProperties properties) {
        BffProperties.Provider provider = properties.provider();
        BffProperties.Client client = properties.client();
        return ClientRegistration.withRegistrationId(properties.registrationId())
                .clientName("Demo authorization server")
                .clientId(client.clientId())
                .clientSecret(client.clientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(client.scopes())
                // PKCE for this confidential client too. Spring adds it automatically only for public
                // clients; requireProofKey also covers this one (the authorization server insists on it).
                .clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build())
                // With the issuer set, every ID token's "iss" must match it exactly; without it,
                // Spring would skip the issuer check.
                .issuerUri(provider.issuer())
                .authorizationUri(provider.authorizationUri())
                .tokenUri(provider.tokenUri())
                .jwkSetUri(provider.jwkSetUri())
                .userInfoUri(provider.userInfoUri())
                .userNameAttributeName(IdTokenClaimNames.SUB)
                // Read by OidcClientInitiatedLogoutSuccessHandler for RP-initiated logout.
                .providerConfigurationMetadata(Map.of("end_session_endpoint", provider.endSessionUri()))
                .build();
    }
}
