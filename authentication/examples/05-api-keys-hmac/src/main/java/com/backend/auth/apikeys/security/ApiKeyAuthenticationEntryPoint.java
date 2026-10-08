package com.backend.auth.apikeys.security;

import java.io.IOException;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 401 (or 400 for a malformed request) with an RFC 6750 {@code WWW-Authenticate: Bearer} challenge and a
 * problem body. The body is the same for unknown, revoked and expired keys.
 */
public final class ApiKeyAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyAuthenticationEntryPoint.class);

    private static final String REALM = "Bearer realm=\"api\"";
    private static final Pattern CREDENTIAL_IN_QUERY =
            Pattern.compile("(^|&)(api[_-]?key|key|access_token|token)=", Pattern.CASE_INSENSITIVE);

    private final ProblemWriter problems;

    public ApiKeyAuthenticationEntryPoint(ProblemWriter problems) {
        this.problems = problems;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {
        if (exception instanceof MalformedCredentialsException) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, REALM + ", error=\"invalid_request\"");
            problems.write(response, HttpStatus.BAD_REQUEST, "Malformed credentials", exception.getMessage());
        }
        else if (exception instanceof BadCredentialsException) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, REALM + ", error=\"invalid_token\"");
            problems.write(response, HttpStatus.UNAUTHORIZED, "Invalid API key", ApiKeyAuthenticationProvider.INVALID_KEY);
        }
        else {
            // No credentials at all (RFC 6750 section 3.1: then the challenge carries no error code).
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, REALM);
            problems.write(response, HttpStatus.UNAUTHORIZED, "Authentication required", missingKeyDetail(request));
        }
    }

    /** A key in the URL is ignored, but the developer deserves to know why the call failed. */
    private static String missingKeyDetail(HttpServletRequest request) {
        String query = request.getQueryString();
        if (query != null && CREDENTIAL_IN_QUERY.matcher(query).find()) {
            log.warn("Ignored a credential in the query string of {} {}; that key is now in URL logs and should be rotated",
                    request.getMethod(), request.getRequestURI());
            return "Credentials in the URL are ignored (they leak into logs). Send the API key in the "
                    + "Authorization header (Bearer) or the X-API-Key header, and rotate the key you just exposed.";
        }
        return "Send an API key in the Authorization header (Bearer) or the X-API-Key header.";
    }
}
