package com.backend.auth.mfa.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 * Adds the second login step to an {@link HttpSecurity}, the way {@code formLogin()} adds the first:
 * <ul>
 *   <li>one {@link SecondFactorAuthenticationFilter} per {@link SecondFactor}, wired with the same session
 *       strategy (new session ID, new CSRF token), security-context repository and saved-request handling that
 *       form login uses;</li>
 *   <li>an entry in Spring Security's "missing factor" handler, so a signed-in user who lacks the second factor is
 *       redirected to {@code /login/totp} instead of receiving a bare 403.</li>
 * </ul>
 */
public final class SecondFactorLoginConfigurer extends AbstractHttpConfigurer<SecondFactorLoginConfigurer, HttpSecurity> {

    private final AuthenticationProvider secondFactorProvider;
    private final AuthorizationManager<Object> passwordStepCompleted;

    public SecondFactorLoginConfigurer(AuthenticationProvider secondFactorProvider,
                                       AuthorizationManager<Object> passwordStepCompleted) {
        this.secondFactorProvider = secondFactorProvider;
        this.passwordStepCompleted = passwordStepCompleted;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void init(HttpSecurity http) {
        LoginUrlAuthenticationEntryPoint secondFactorPage = new LoginUrlAuthenticationEntryPoint(SecondFactor.TOTP.loginPage());
        ExceptionHandlingConfigurer<HttpSecurity> exceptions = http.getConfigurer(ExceptionHandlingConfigurer.class);
        for (SecondFactor factor : SecondFactor.values()) {
            exceptions.defaultDeniedHandlerForMissingAuthority(secondFactorPage, factor.authority());
        }
    }

    @Override
    public void configure(HttpSecurity http) {
        // A dedicated manager: these tokens must never reach the password provider, and vice versa.
        AuthenticationManager authenticationManager = new ProviderManager(secondFactorProvider);
        for (SecondFactor factor : SecondFactor.values()) {
            http.addFilterAfter(createFilter(http, authenticationManager, factor), UsernamePasswordAuthenticationFilter.class);
        }
    }

    private SecondFactorAuthenticationFilter createFilter(HttpSecurity http, AuthenticationManager authenticationManager,
                                                          SecondFactor factor) {
        SecondFactorAuthenticationFilter filter = new SecondFactorAuthenticationFilter(factor, passwordStepCompleted);
        filter.setAuthenticationManager(authenticationManager);
        filter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
        // Store the upgraded Authentication in the HTTP session (the default would keep it for this request only).
        filter.setSecurityContextRepository(http.getSharedObject(SecurityContextRepository.class));
        // Privilege changes, so the session ID and CSRF token change too (session fixation defense, as at the password step).
        filter.setSessionAuthenticationStrategy(http.getSharedObject(SessionAuthenticationStrategy.class));

        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        RequestCache requestCache = http.getSharedObject(RequestCache.class);
        if (requestCache != null) {
            successHandler.setRequestCache(requestCache);
        }
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(new SecondFactorFailureHandler(factor));

        // MFA mode: if the session already holds an Authentication for the same user, the filter copies its factor
        // authorities (FACTOR_PASSWORD) into the new one instead of replacing it. @EnableMultiFactorAuthentication
        // turns this on for Spring's own filters; ours is created here, so it is set explicitly.
        filter.setMfaEnabled(true);
        return postProcess(filter);
    }
}
