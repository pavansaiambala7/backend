package com.backend.auth.apikeys.security;

import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Extracts an API key from {@code Authorization: Bearer <key>} or {@code X-API-Key: <key>}.
 *
 * <p>Deliberately never reads the query string or form parameters: URLs end up in access logs, proxy logs,
 * browser history and {@code Referer} headers, so a key sent there must be treated as leaked, not accepted.
 */
public final class ApiKeyAuthenticationConverter implements AuthenticationConverter {

    public static final String API_KEY_HEADER = "X-API-Key";

    private static final Pattern BEARER = Pattern.compile("^Bearer +([^\\s]+) *$", Pattern.CASE_INSENSITIVE);

    @Override
    public Authentication convert(HttpServletRequest request) {
        List<String> authorization = values(request, HttpHeaders.AUTHORIZATION);
        List<String> apiKeyHeader = values(request, API_KEY_HEADER);
        List<String> bearer = authorization.stream()
                .filter(value -> value.regionMatches(true, 0, "Bearer", 0, "Bearer".length()))
                .toList();

        // RFC 6750 section 2: a client MUST NOT send a token in more than one way. Picking one of two keys
        // would make logs and audit trails ambiguous, so refuse instead of guessing.
        if (bearer.size() + apiKeyHeader.size() > 1) {
            throw new MalformedCredentialsException("Send exactly one API key, in either Authorization or X-API-Key");
        }
        if (!apiKeyHeader.isEmpty()) {
            return ApiKeyAuthenticationToken.unauthenticated(apiKeyHeader.getFirst().strip());
        }
        if (!bearer.isEmpty()) {
            Matcher matcher = BEARER.matcher(bearer.getFirst());
            if (!matcher.matches()) {
                throw new MalformedCredentialsException("Malformed Authorization header; expected 'Bearer <api key>'");
            }
            return ApiKeyAuthenticationToken.unauthenticated(matcher.group(1));
        }
        return null;   // no API key: continue anonymously and let authorization answer 401
    }

    private static List<String> values(HttpServletRequest request, String header) {
        return Collections.list(request.getHeaders(header));
    }
}
