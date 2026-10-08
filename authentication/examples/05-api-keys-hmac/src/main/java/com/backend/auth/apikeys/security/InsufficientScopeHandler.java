package com.backend.auth.apikeys.security;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** 403: the key is valid but lacks the scope. A different key would help; sending this one again would not. */
public final class InsufficientScopeHandler implements AccessDeniedHandler {

    private final ProblemWriter problems;

    public InsufficientScopeHandler(ProblemWriter problems) {
        this.problems = problems;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
            throws IOException {
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"api\", error=\"insufficient_scope\"");
        problems.write(response, HttpStatus.FORBIDDEN, "Insufficient scope",
                "This API key does not have the scope required for this operation.");
    }
}
