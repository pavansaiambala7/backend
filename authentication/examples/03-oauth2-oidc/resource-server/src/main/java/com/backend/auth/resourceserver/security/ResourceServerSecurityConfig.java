package com.backend.auth.resourceserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
class ResourceServerSecurityConfig {

    @Bean
    SecurityFilterChain apiSecurityFilterChain(HttpSecurity http, ResourceServerProperties properties) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                // Scopes arrive as SCOPE_ authorities (from the "scope" claim).
                .requestMatchers(HttpMethod.GET, "/api/orders").hasAuthority("SCOPE_orders.read")
                // Deny by default: a new endpoint is closed until someone writes a rule for it.
                .anyRequest().denyAll())
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(Customizer.withDefaults())
                // RFC 9728 metadata at /.well-known/oauth-protected-resource (served by Spring Security 7,
                // and linked from every 401's WWW-Authenticate header): tells a client which
                // authorization server issues tokens for this API and which scopes it understands.
                .protectedResourceMetadata(metadata -> metadata.protectedResourceMetadataCustomizer(resource -> resource
                    .resourceName("Orders API")
                    .authorizationServer(properties.issuer())
                    .scope("orders.read"))))
            // Every request carries its own token: no session, no session cookie.
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // CSRF exploits credentials the browser attaches by itself (cookies). A bearer token in the
            // Authorization header is never attached automatically, and this API has no cookies.
            .csrf(csrf -> csrf.disable());
        return http.build();
    }

    /**
     * Verifies signatures with the authorization server's published keys. Keys are fetched lazily on the
     * first request, cached, and re-fetched when a token arrives with an unknown {@code kid} (rotation).
     */
    @Bean
    JwtDecoder jwtDecoder(ResourceServerProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri())
                // Algorithm allowlist: the token header cannot talk us into HS256 (with the public key
                // as the HMAC secret) or "none". Only RS256 signatures from the JWKS are accepted.
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(AccessTokenValidators.forApi(properties));
        return decoder;
    }
}
