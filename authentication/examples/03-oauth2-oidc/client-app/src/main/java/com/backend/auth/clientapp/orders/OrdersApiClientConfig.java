package com.backend.auth.clientapp.orders;

import java.net.http.HttpClient;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;

import com.backend.auth.clientapp.BffProperties;

@Configuration(proxyBeanMethods = false)
class OrdersApiClientConfig {

    /**
     * Supplies the signed-in user's access token, refreshing it with the refresh token when it has
     * expired. If there is no token at all, the user has to log in again (authorizationCode()).
     */
    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrations,
                                                          OAuth2AuthorizedClientRepository authorizedClients) {
        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .build();
        DefaultOAuth2AuthorizedClientManager manager =
                new DefaultOAuth2AuthorizedClientManager(clientRegistrations, authorizedClients);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    /** A RestClient that adds "Authorization: Bearer &lt;the current user's access token&gt;" to each call. */
    @Bean
    RestClient ordersRestClient(BffProperties properties,
                                OAuth2AuthorizedClientManager authorizedClientManager,
                                OAuth2AuthorizedClientRepository authorizedClients) {
        OAuth2ClientHttpRequestInterceptor bearerToken = new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
        // If the API answers 401 invalid_token (token revoked, key rotated, ...), forget the stored token
        // instead of sending the same rejected token again on every request.
        bearerToken.setAuthorizationFailureHandler(
                OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(authorizedClients));

        BffProperties.OrdersApi ordersApi = properties.ordersApi();
        HttpClient httpClient = HttpClient.newBuilder().connectTimeout(ordersApi.connectTimeout()).build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(ordersApi.readTimeout());

        return RestClient.builder()
                .baseUrl(ordersApi.baseUrl())
                .requestFactory(requestFactory)
                .requestInterceptor(bearerToken)
                .build();
    }
}
