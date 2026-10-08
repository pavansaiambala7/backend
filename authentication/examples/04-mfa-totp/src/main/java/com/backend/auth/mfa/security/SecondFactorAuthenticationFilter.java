package com.backend.auth.mfa.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Processes {@code POST /login/totp} and {@code POST /login/recovery-code} (parameter {@code code}).
 *
 * <p>Authentication filters run before authorization, so the URL rules in {@code SecurityConfig} do not protect
 * these POSTs: the filter itself checks that the session passed the password step recently.
 */
public class SecondFactorAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final SecondFactor factor;
    private final AuthorizationManager<Object> passwordStepCompleted;
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

    public SecondFactorAuthenticationFilter(SecondFactor factor, AuthorizationManager<Object> passwordStepCompleted) {
        super(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, factor.loginPage()));
        this.factor = factor;
        this.passwordStepCompleted = passwordStepCompleted;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        Authentication current = securityContextHolderStrategy.getContext().getAuthentication();
        AuthorizationResult passwordStep = passwordStepCompleted.authorize(() -> current, request);
        if (current == null || passwordStep == null || !passwordStep.isGranted()) {
            // A code on its own identifies nobody; it only completes a login whose password step just succeeded.
            throw new InsufficientAuthenticationException("Sign in with your password first");
        }
        String code = request.getParameter("code");
        SecondFactorCodeToken token = new SecondFactorCodeToken(current.getName(), code == null ? "" : code, factor);
        token.setDetails(authenticationDetailsSource.buildDetails(request));
        return getAuthenticationManager().authenticate(token);
    }

    @Override
    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        super.setSecurityContextHolderStrategy(securityContextHolderStrategy);
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }
}
