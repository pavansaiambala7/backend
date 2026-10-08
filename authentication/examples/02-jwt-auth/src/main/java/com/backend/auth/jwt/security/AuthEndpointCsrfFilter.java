package com.backend.auth.jwt.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * CSRF defense for the endpoints that read or set the refresh-token cookie ({@code POST /auth/**}).
 *
 * <p>Browsers attach cookies automatically, so without this a malicious page could make the victim's
 * browser call {@code /auth/refresh} or {@code /auth/logout}. It cannot read the response, but it could
 * log the user out, or rotate the token behind the real client's back so that the client's next refresh
 * looks like reuse and the whole family is revoked. {@code SameSite=Strict} already stops cross-site
 * requests in current browsers, but not same-site ones (a compromised sibling subdomain is "same site")
 * and not in old or misconfigured clients. So three independent checks are layered on top:
 *
 * <ol>
 *   <li><b>Required custom header</b> {@value #REQUIRED_HEADER}. HTML forms cannot set headers, and a
 *       cross-origin {@code fetch} with a custom header triggers a CORS preflight this server does not
 *       approve. Its value is not a secret: its presence is the proof the request came from our own
 *       JavaScript (or a non-browser client), which is why no token synchronization is needed.</li>
 *   <li><b>Origin allowlist.</b> Browsers send {@code Origin} on POST; if present it must be one of ours.
 *       Clients that send none (curl, mobile apps) are not browsers, so CSRF does not apply to them.</li>
 *   <li><b>Fetch Metadata.</b> {@code Sec-Fetch-Site: cross-site} is refused outright.</li>
 * </ol>
 *
 * <p>The bearer-token API needs none of this: browsers never add an {@code Authorization} header on their own.
 */
public final class AuthEndpointCsrfFilter extends OncePerRequestFilter {

    public static final String REQUIRED_HEADER = "X-CSRF-Protection";

    private static final Logger log = LoggerFactory.getLogger(AuthEndpointCsrfFilter.class);
    private static final String REJECTION_BODY =
            "{\"error\":\"csrf_check_failed\",\"error_description\":\"Cross-site request refused\"}";

    private final Set<String> allowedOrigins;

    public AuthEndpointCsrfFilter(Set<String> allowedOrigins) {
        this.allowedOrigins = Set.copyOf(allowedOrigins);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !HttpMethod.POST.matches(request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String rejection = rejectionReason(request);
        if (rejection != null) {
            log.info("Refused {} {}: {}", request.getMethod(), request.getRequestURI(), rejection);
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getOutputStream().write(REJECTION_BODY.getBytes(StandardCharsets.UTF_8));
            return;
        }
        chain.doFilter(request, response);
    }

    private String rejectionReason(HttpServletRequest request) {
        if ("cross-site".equals(request.getHeader("Sec-Fetch-Site"))) {
            return "Sec-Fetch-Site is cross-site";
        }
        String origin = request.getHeader("Origin");
        if (origin != null && !allowedOrigins.contains(origin)) {
            return "Origin not allowed";   // includes the opaque "null" origin of sandboxed frames
        }
        String marker = request.getHeader(REQUIRED_HEADER);
        if (marker == null || marker.isBlank()) {
            return "missing " + REQUIRED_HEADER + " header";
        }
        return null;
    }
}
