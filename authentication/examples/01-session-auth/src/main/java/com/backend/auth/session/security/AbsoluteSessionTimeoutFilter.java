package com.backend.auth.session.security;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Ends a session a fixed time after login, however active it is. The container only enforces an
 * idle timeout, which an attacker holding a stolen session ID can defeat forever by sending a
 * request every few minutes.
 */
final class AbsoluteSessionTimeoutFilter extends OncePerRequestFilter {

    /**
     * Set at login by {@link RecordAuthenticationTimeSuccessHandler}. {@code session.getCreationTime()}
     * is not used because the (anonymous) session may have been created long before the login.
     */
    static final String AUTHENTICATED_AT = AbsoluteSessionTimeoutFilter.class.getName() + ".AUTHENTICATED_AT";

    private final Duration maxSessionAge;
    private final Clock clock;

    AbsoluteSessionTimeoutFilter(Duration maxSessionAge, Clock clock) {
        this.maxSessionAge = maxSessionAge;
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null
                && session.getAttribute(AUTHENTICATED_AT) instanceof Instant authenticatedAt
                && !clock.instant().isBefore(authenticatedAt.plus(maxSessionAge))) {
            session.invalidate();
            SecurityContextHolder.clearContext();
            response.sendRedirect(request.getContextPath() + "/login?expired");
            return;
        }
        chain.doFilter(request, response);
    }
}
