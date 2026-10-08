package com.backend.auth.jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
class SecurityConfig {

    /**
     * Token endpoints and the JWKS. Public by design: login checks the password itself, and refresh and
     * logout are authorized by the refresh-token cookie, which is why they get the CSRF filter.
     */
    @Bean
    @Order(1)
    SecurityFilterChain tokenEndpoints(HttpSecurity http, CsrfProperties csrfProperties) throws Exception {
        http
            .securityMatcher("/auth/**", "/.well-known/jwks.json")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json").permitAll()
                .requestMatchers(HttpMethod.POST, "/auth/login", "/auth/refresh", "/auth/logout").permitAll()
                .anyRequest().denyAll())
            // Spring's synchronizer-token CSRF needs a server-side session, which this API does not have.
            // AuthEndpointCsrfFilter protects the cookie endpoints instead (see its Javadoc).
            .csrf(csrf -> csrf.disable())
            .addFilterBefore(new AuthEndpointCsrfFilter(csrfProperties.allowedOrigins()), AuthorizationFilter.class)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(cache -> cache.disable())
            .headers(SecurityConfig::apiHeaders);
        return http.build();
    }

    /** Everything else: a stateless resource server that accepts only our RS256 access tokens. */
    @Bean
    @Order(2)
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/error").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/me").authenticated()
                // The default JwtAuthenticationConverter maps the "scope" claim to SCOPE_ authorities.
                .requestMatchers(HttpMethod.GET, "/api/orders/**").hasAuthority("SCOPE_orders:read")
                .requestMatchers(HttpMethod.POST, "/api/orders/**").hasAuthority("SCOPE_orders:write")
                .anyRequest().denyAll())
            // Uses the JwtDecoder bean (JwtConfig): RS256 only, iss, aud, typ, exp/nbf with a small skew.
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(Customizer.withDefaults())
                // Spring Security 7 serves RFC 9728 metadata at /.well-known/oauth-protected-resource and
                // links it from WWW-Authenticate. Its defaults claim mTLS-bound tokens; make it truthful.
                .protectedResourceMetadata(metadata -> metadata.protectedResourceMetadataCustomizer(resource -> resource
                    .resourceName("JWT demo API")
                    .scope("orders:read")
                    .scope("orders:write")
                    .tlsClientCertificateBoundAccessTokens(false))))
            // Safe only because this API authenticates with the Authorization header, never cookies.
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(cache -> cache.disable())
            .headers(SecurityConfig::apiHeaders);
        return http.build();
    }

    /**
     * Checks usernames and passwords for {@code POST /auth/login}. Unknown users still cost one
     * password-hash computation, so response times do not reveal which accounts exist.
     */
    @Bean
    AuthenticationManager loginAuthenticationManager(InMemoryUserDetailsManager users, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(users);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsPasswordService(users);   // re-hash outdated hashes on successful login
        return new ProviderManager(provider);
    }

    private static void apiHeaders(HeadersConfigurer<HttpSecurity> headers) {
        headers
            // JSON only: nothing here should ever be rendered, framed or loaded as a script.
            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
            .referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER));
    }
}
