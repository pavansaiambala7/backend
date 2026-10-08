package com.backend.auth.clientapp.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Backend for Frontend: the browser authenticates to this app with a session cookie only. The OAuth
 * tokens (access, refresh, ID) are kept in the server-side session and never sent to the browser, so
 * script injected into the page (XSS) has no token to steal.
 */
@Configuration(proxyBeanMethods = false)
class BffSecurityConfig {

    private static final String CONTENT_SECURITY_POLICY =
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

    @Bean
    SecurityFilterChain bffSecurityFilterChain(HttpSecurity http,
                                               ClientRegistrationRepository clientRegistrations,
                                               @Value("${server.servlet.session.cookie.name}") String sessionCookieName)
            throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/logged-out", "/error").permitAll()
                .anyRequest().authenticated())
            // JSON endpoints answer 401 instead of redirecting: a fetch() from the frontend cannot follow
            // a redirect to the authorization server's login page anyway; the frontend navigates instead.
            .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    PathPatternRequestMatcher.pathPattern("/api/**")))
            // OpenID Connect login: authorization code + PKCE, state (CSRF on the callback) and nonce
            // (ID token replay) are generated, stored in the session and checked by Spring Security.
            // The session ID changes after login (session fixation protection, on by default).
            .oauth2Login(Customizer.withDefaults())
            // CSRF protection is on (the default) because the session cookie is sent automatically by
            // the browser; this also makes /logout POST-only, so a link cannot sign the user out.
            .csrf(Customizer.withDefaults())
            .logout(logout -> logout
                .invalidateHttpSession(true)              // also drops the tokens stored in the session
                .deleteCookies(sessionCookieName)
                .logoutSuccessHandler(rpInitiatedLogout(clientRegistrations)))
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY)));
        return http.build();
    }

    /**
     * Stores each user's tokens in their HTTP session. The default (an in-memory map keyed by user name)
     * would keep tokens after logout and share them between all sessions of one user.
     */
    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    /**
     * After the local logout, send the browser to the provider's end_session_endpoint with the ID token
     * as a hint, so the authorization server's session ends too. Otherwise the next "sign in" would
     * silently log the same user back in.
     */
    private static LogoutSuccessHandler rpInitiatedLogout(ClientRegistrationRepository clientRegistrations) {
        OidcClientInitiatedLogoutSuccessHandler handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrations);
        // Must be registered at the authorization server exactly (post_logout_redirect_uris).
        handler.setPostLogoutRedirectUri("{baseUrl}/logged-out");
        return handler;
    }
}
