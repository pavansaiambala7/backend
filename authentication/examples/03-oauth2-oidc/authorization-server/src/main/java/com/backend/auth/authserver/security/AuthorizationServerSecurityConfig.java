package com.backend.auth.authserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.backend.auth.authserver.AuthServerProperties;

/**
 * Two filter chains, the standard Spring Authorization Server layout:
 * <ol>
 *   <li>the protocol endpoints (authorize, token, JWKS, discovery, userinfo, logout, revoke, introspect);</li>
 *   <li>everything else, which here is only the login form where the user authenticates.</li>
 * </ol>
 */
@Configuration(proxyBeanMethods = false)
class AuthorizationServerSecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .oauth2AuthorizationServer(authorizationServer -> {
                // This chain only handles the protocol endpoints (CSRF does not apply to them:
                // they are authenticated by client credentials, codes, PKCE and tokens, not cookies).
                http.securityMatcher(authorizationServer.getEndpointsMatcher());
                // OpenID Connect 1.0: discovery, ID tokens, /userinfo and RP-initiated logout.
                // Dynamic client registration stays disabled (the default).
                authorizationServer.oidc(Customizer.withDefaults());
            })
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
            // /userinfo is called with the access token as a bearer token.
            .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
            // A browser hitting /oauth2/authorize without a session is sent to the login page;
            // API clients get a 401 instead of an HTML redirect.
            .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain loginSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated())
            // Spring's generated login page. CSRF stays on (login CSRF), the session ID changes at
            // login (session fixation), and one generic error covers unknown user and wrong password.
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

    /**
     * The issuer is set explicitly instead of being derived from each request's Host header, so the
     * value in tokens and metadata cannot be influenced by a client and stays stable behind proxies.
     */
    @Bean
    AuthorizationServerSettings authorizationServerSettings(AuthServerProperties properties) {
        return AuthorizationServerSettings.builder()
                .issuer(properties.issuer())
                .build();
    }

    /**
     * Lets the session registry used for the ID token's {@code sid} claim and for RP-initiated logout
     * forget sessions that expire or are invalidated.
     */
    @Bean
    HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}
