package com.backend.auth.session.security;

import java.time.Clock;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration(proxyBeanMethods = false)
class SecurityConfig {

    private static final String CONTENT_SECURITY_POLICY =
            "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            SessionPolicyProperties sessionPolicy,
                                            LoginAttemptService loginAttempts,
                                            SessionRegistry sessionRegistry,
                                            Clock clock,
                                            @Value("${server.servlet.session.cookie.name:JSESSIONID}") String sessionCookieName)
            throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/login", "/register", "/error", "/css/**").permitAll()
                .anyRequest().authenticated())
            .formLogin(form -> form
                .loginPage("/login")
                .successHandler(new RecordAuthenticationTimeSuccessHandler(clock))
                // One URL for unknown user, wrong password and anything else: no account enumeration.
                .failureUrl("/login?error")
                .permitAll())
            .sessionManagement(session -> session
                // Default since Servlet 3.1, made explicit because it is the session-fixation defense:
                // the ID an attacker may have planted before login is worthless after it.
                .sessionFixation(fixation -> fixation.changeSessionId())
                .sessionConcurrency(concurrency -> concurrency
                    .maximumSessions(sessionPolicy.maximumPerUser())
                    // Expire the oldest session instead of refusing the new login: refusing would let
                    // a thief holding a stolen session lock the real user out.
                    .maxSessionsPreventsLogin(false)
                    .expiredUrl("/login?expired")
                    .sessionRegistry(sessionRegistry)))
            // Session-backed synchronizer token with per-response masking (BREACH-resistant). It also
            // covers /login (login CSRF) and /logout. On by default; stated so nobody "simplifies" it away.
            .csrf(Customizer.withDefaults())
            .logout(logout -> logout
                .logoutUrl("/logout")                 // POST only, because CSRF protection is enabled
                .invalidateHttpSession(true)          // deleting only the cookie would leave a stolen ID valid
                .clearAuthentication(true)
                .deleteCookies(sessionCookieName)
                // Only sent over HTTPS (browsers ignore it on insecure origins).
                .addLogoutHandler(new HeaderWriterLogoutHandler(
                        new ClearSiteDataHeaderWriter(ClearSiteDataHeaderWriter.Directive.COOKIES)))
                .logoutSuccessUrl("/login?logout"))
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY))
                // Written only on HTTPS requests; in production that is every request.
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(Duration.ofDays(365).toSeconds())))
            .addFilterAfter(new AbsoluteSessionTimeoutFilter(sessionPolicy.absoluteTimeout(), clock), HeaderWriterFilter.class)
            .addFilterBefore(new CrossSiteRequestBlockingFilter(), CsrfFilter.class)
            .addFilterBefore(new LoginThrottleFilter(loginAttempts), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Tracks sessions per user for maximumSessions. In memory, so it only sees this instance;
     * with several instances use Spring Session's SpringSessionBackedSessionRegistry.
     */
    @Bean
    SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /** Tells the SessionRegistry when the container destroys a session (logout, idle timeout). */
    @Bean
    HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}
