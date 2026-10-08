package com.backend.auth.session.security;

import java.io.IOException;
import java.time.Clock;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/**
 * Stores the login time in the (already rotated) session for the absolute timeout, then redirects
 * to the page the user originally asked for, or "/".
 */
final class RecordAuthenticationTimeSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final Clock clock;

    RecordAuthenticationTimeSuccessHandler(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        request.getSession().setAttribute(AbsoluteSessionTimeoutFilter.AUTHENTICATED_AT, clock.instant());
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
