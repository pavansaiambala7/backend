package com.backend.auth.apikeys.security;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

import com.backend.auth.apikeys.admin.AdminUser;
import com.backend.auth.apikeys.admin.AdminUserDetailsService;
import com.backend.auth.apikeys.apikey.ApiKeyVerifier;
import com.backend.auth.apikeys.webhook.PaymentWebhookProperties;
import com.backend.auth.apikeys.webhook.WebhookSignatureFilter;
import com.backend.auth.apikeys.webhook.WebhookSignatureVerifier;

/**
 * Three stateless filter chains, one per kind of caller:
 * <ol>
 * <li>{@code /admin/**}: administrators (HTTP Basic, Argon2id) manage keys. API keys are not accepted here,
 *     so a leaked key cannot mint more keys.</li>
 * <li>{@code /webhooks/**}: the payment provider, authenticated by an HMAC signature over the raw body.</li>
 * <li>everything else: integrations, authenticated by API key, authorized by the key's scopes.</li>
 * </ol>
 * CSRF protection is off in all three for the same reason: none of them accepts an ambient credential
 * (no cookies, no session, no browser-cached Basic credentials), so a cross-site request cannot borrow one.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain adminChain(HttpSecurity http, AdminUserDetailsService admins, PasswordEncoder passwordEncoder,
            ProblemWriter problems) throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(admins);
        provider.setPasswordEncoder(passwordEncoder);
        // No "WWW-Authenticate: Basic" challenge: browsers never show a login dialog for /admin and therefore never
        // cache Basic credentials, which would be an ambient credential that CSRF could ride on. curl -u still works.
        AuthenticationEntryPoint entryPoint = (request, response, exception) -> problems.write(response,
                HttpStatus.UNAUTHORIZED, "Authentication required", "Administrator credentials are required.");

        http
            .securityMatcher("/admin/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().hasRole(AdminUser.ROLE))
            .httpBasic(basic -> basic.authenticationEntryPoint(entryPoint))
            .authenticationManager(new ProviderManager(provider))
            .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(entryPoint))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(cache -> cache.disable())
            .csrf(csrf -> csrf.disable())
            .headers(SecurityConfig::apiHeaders);
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain webhookChain(HttpSecurity http, WebhookSignatureVerifier paymentWebhookVerifier,
            PaymentWebhookProperties properties, ProblemWriter problems) throws Exception {
        var signatureFilter = new WebhookSignatureFilter(paymentWebhookVerifier,
                Math.toIntExact(properties.maxBodySize().toBytes()), problems);

        http
            .securityMatcher("/webhooks/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/webhooks/payments").hasAuthority(WebhookSignatureFilter.PAYMENTS_PROVIDER)
                .anyRequest().denyAll())
            .addFilterBefore(signatureFilter, AuthorizationFilter.class)
            .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint((request, response, exception) ->
                problems.write(response, HttpStatus.UNAUTHORIZED, "Webhook rejected", "A valid signature is required.")))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(cache -> cache.disable())
            .csrf(csrf -> csrf.disable())
            .headers(SecurityConfig::apiHeaders);
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain apiChain(HttpSecurity http, ApiKeyVerifier verifier, ProblemWriter problems) throws Exception {
        var entryPoint = new ApiKeyAuthenticationEntryPoint(problems);
        var apiKeyFilter = new AuthenticationFilter(
                new ProviderManager(new ApiKeyAuthenticationProvider(verifier)), new ApiKeyAuthenticationConverter());
        // The default success handler redirects (it was written for login forms); an API just continues the chain.
        apiKeyFilter.setSuccessHandler((request, response, authentication) -> { });
        apiKeyFilter.setFailureHandler(new AuthenticationEntryPointFailureHandler(entryPoint));

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/error").permitAll()
                .requestMatchers(HttpMethod.GET, "/v1/me").authenticated()
                .requestMatchers(HttpMethod.GET, "/v1/orders", "/v1/orders/**").hasAuthority("SCOPE_orders:read")
                .requestMatchers(HttpMethod.POST, "/v1/orders").hasAuthority("SCOPE_orders:write")
                .anyRequest().denyAll())
            .addFilterBefore(apiKeyFilter, AuthorizationFilter.class)
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(entryPoint)
                .accessDeniedHandler(new InsufficientScopeHandler(problems)))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(cache -> cache.disable())
            .csrf(csrf -> csrf.disable())
            .headers(SecurityConfig::apiHeaders);
        return http.build();
    }

    /**
     * Administrator passwords: Argon2id with the OWASP minimum (m=19456 KiB, t=2, p=1) for new hashes; bcrypt
     * hashes from a legacy store still verify. API keys do not use this encoder (see ApiKeyHasher for why).
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        String defaultId = "argon2";
        return new DelegatingPasswordEncoder(defaultId, Map.of(
                defaultId, new Argon2PasswordEncoder(16, 32, 1, 19_456, 2),
                "bcrypt", new BCryptPasswordEncoder(12)));
    }

    private static void apiHeaders(HeadersConfigurer<HttpSecurity> headers) {
        headers
            // JSON only: nothing here should ever be rendered, framed or loaded as a script.
            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
            .referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER));
    }
}
