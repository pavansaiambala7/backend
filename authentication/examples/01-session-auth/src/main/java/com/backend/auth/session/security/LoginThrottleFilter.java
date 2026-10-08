package com.backend.auth.session.security;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rejects login attempts from a blocked username/IP before they reach the password check.
 * Running first matters twice: a blocked attacker cannot learn whether a guess was right, and
 * the server does not spend an Argon2id computation (19 MiB of memory) on every flood request.
 */
final class LoginThrottleFilter extends OncePerRequestFilter {

    private static final RequestMatcher LOGIN_ATTEMPT = PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login");

    private final LoginAttemptService attempts;

    LoginThrottleFilter(LoginAttemptService attempts) {
        this.attempts = attempts;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !LOGIN_ATTEMPT.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<Duration> wait = attempts.retryAfter(request.getParameter("username"), request.getRemoteAddr());
        if (wait.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }
        long seconds = Math.max(1, (wait.get().toMillis() + 999) / 1000);
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(seconds));
        response.setContentType("text/plain;charset=UTF-8");
        // Same text for existing and non-existing usernames: the throttle must not enumerate accounts.
        response.getWriter().write("Too many failed sign-in attempts. Please wait " + seconds + " seconds and try again.");
    }
}
