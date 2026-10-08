package com.backend.auth.mfa.security;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Where a failed second-factor attempt goes. The partially authenticated session survives a wrong code (the user
 * may retry, within the throttle), so only the error page differs.
 */
public class SecondFactorFailureHandler implements AuthenticationFailureHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final String errorUrl;

    public SecondFactorFailureHandler(SecondFactor factor) {
        this.errorUrl = factor.loginPage() + "?error";
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        if (exception instanceof SecondFactorThrottledException throttled) {
            writeTooManyRequests(response, throttled);
        } else if (exception instanceof InsufficientAuthenticationException) {
            // No recent password step in this session: start the login again.
            redirectStrategy.sendRedirect(request, response, "/login");
        } else {
            redirectStrategy.sendRedirect(request, response, errorUrl);
        }
    }

    /** 429 with {@code Retry-After}, shared with the enrollment confirmation endpoint. */
    public static void writeTooManyRequests(HttpServletResponse response, SecondFactorThrottledException exception)
            throws IOException {
        long seconds = exception.retryAfterSeconds();
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(seconds));
        response.setContentType(MediaType.TEXT_PLAIN_VALUE + ";charset=UTF-8");
        response.getWriter().write("Too many wrong codes. Please wait " + seconds + " seconds and try again.\n");
    }
}
