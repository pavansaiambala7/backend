package com.backend.auth.mfa.security;

import java.time.Clock;
import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

import com.backend.auth.mfa.recovery.RecoveryCodeService;
import com.backend.auth.mfa.totp.TotpAuthenticator;
import com.backend.auth.mfa.totp.TotpEnrollmentService;

/**
 * Two-step login with Spring Security 7's multi-factor support.
 *
 * <p>Every successful authentication adds a factor authority with a timestamp: form login adds
 * {@code FACTOR_PASSWORD}, this application's second step adds {@code FACTOR_TOTP} or {@code FACTOR_RECOVERY_CODE}.
 * Access rules then require combinations of factors. A session that holds only {@code FACTOR_PASSWORD} is
 * <em>partially authenticated</em>: it can reach the second-factor pages and, for users without an authenticator yet,
 * the enrollment pages, and nothing else.
 */
@Configuration(proxyBeanMethods = false)
// Empty authorities: no factor rule is published by the annotation (the factory below defines it), but the
// annotation still switches Spring's authentication filters into MFA mode, so signing in again adds a factor to
// the session's Authentication instead of replacing it.
@EnableMultiFactorAuthentication(authorities = {})
class SecurityConfig {

    private static final String CONTENT_SECURITY_POLICY =
            "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    /**
     * Makes every rule built from the factory ({@code authenticated()}, {@code hasRole(..)}, ...) also require
     * password AND (TOTP OR recovery code). With a single combination,
     * {@code @EnableMultiFactorAuthentication(authorities = {"FACTOR_PASSWORD", "FACTOR_TOTP"})} would do the same.
     */
    @Bean
    DefaultAuthorizationManagerFactory<Object> authorizationManagerFactory() {
        AllRequiredFactorsAuthorizationManager<Object> passwordAndTotp = AllRequiredFactorsAuthorizationManager.builder()
                .requireFactor(factor -> factor.passwordAuthority())
                .requireFactor(factor -> factor.authority(SecondFactor.TOTP.authority()))
                .build();
        AllRequiredFactorsAuthorizationManager<Object> passwordAndRecoveryCode = AllRequiredFactorsAuthorizationManager.builder()
                .requireFactor(factor -> factor.passwordAuthority())
                .requireFactor(factor -> factor.authority(SecondFactor.RECOVERY_CODE.authority()))
                .build();
        DefaultAuthorizationManagerFactory<Object> factory = new DefaultAuthorizationManagerFactory<>();
        factory.setAdditionalAuthorization(AllRequiredFactorsAuthorizationManager.anyOf(passwordAndTotp, passwordAndRecoveryCode));
        return factory;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            SecondFactorProperties secondFactor,
                                            UserDetailsService users,
                                            SecondFactorThrottle throttle,
                                            TotpAuthenticator totp,
                                            RecoveryCodeService recoveryCodes,
                                            TotpEnrollmentService enrollment,
                                            Clock clock) throws Exception {
        AuthorizationManager<Object> passwordStepCompleted = passwordStepCompletedWithin(secondFactor.timeout(), clock);
        // NIST SP 800-63B-4, 4.1.2.1: binding a new authenticator requires authentication at the highest level the
        // account already has. With no second factor yet that is the password; once one exists, adding another
        // would need both factors, so this rule only lets accounts without an authenticator enroll.
        AuthorizationManager<Object> mayEnrollFirstAuthenticator = AuthorizationManagers.allOf(
                passwordStepCompleted,
                (authentication, object) -> new AuthorizationDecision(!enrollment.isEnrolled(authentication.get().getName())));

        SecondFactorAuthenticationProvider secondFactorProvider =
                new SecondFactorAuthenticationProvider(users, throttle, totp, recoveryCodes, clock);

        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/login", "/error", "/css/**").permitAll()
                // .access(..) uses the manager as-is, without the factory's extra factor requirement.
                .requestMatchers(SecondFactor.TOTP.loginPage(), SecondFactor.RECOVERY_CODE.loginPage())
                    .access(passwordStepCompleted)
                .requestMatchers("/mfa/totp/enroll", "/mfa/totp/confirm").access(mayEnrollFirstAuthenticator)
                // Built from the factory: authenticated AND password AND (TOTP OR recovery code).
                .anyRequest().authenticated())
            .formLogin(form -> form
                .loginPage("/login")
                .failureUrl("/login?error")
                .permitAll())
            .with(new SecondFactorLoginConfigurer(secondFactorProvider, passwordStepCompleted))
            .logout(logout -> logout
                .logoutUrl("/logout")                 // POST only, because CSRF protection is enabled
                .logoutSuccessUrl("/login?logout"))
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY))
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(Duration.ofDays(365).toSeconds())));
        // Left at their secure defaults: CSRF protection on every POST (including /login/totp), session ID change
        // at each login step, and "Cache-Control: no-store" on every response (secrets and recovery codes are
        // rendered into pages, and must not stay in a browser or proxy cache).
        return http.build();
    }

    /** {@code FACTOR_PASSWORD} present and issued within {@code timeout}, measured with the application clock. */
    private static AuthorizationManager<Object> passwordStepCompletedWithin(Duration timeout, Clock clock) {
        AllRequiredFactorsAuthorizationManager<Object> manager = AllRequiredFactorsAuthorizationManager.builder()
                .requireFactor(factor -> factor.passwordAuthority().validDuration(timeout))
                .build();
        manager.setClock(clock);
        return manager;
    }
}
