package com.backend.auth.session.security;

import java.io.IOException;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Defense in depth on top of the CSRF token: browsers send {@code Sec-Fetch-Site}, which page
 * scripts cannot forge, so a state-changing request that a browser labels "cross-site" was
 * started by another site and is refused outright. Requests without the header (older browsers,
 * curl) fall through to the CSRF token check, which remains the primary control.
 *
 * <p>This app has no endpoint that legitimately receives cross-site POSTs. Apps with a SAML ACS or
 * OIDC {@code form_post} callback must exempt exactly those paths.
 */
final class CrossSiteRequestBlockingFilter extends OncePerRequestFilter {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        boolean unsafeMethod = !SAFE_METHODS.contains(request.getMethod());
        if (unsafeMethod && "cross-site".equals(request.getHeader("Sec-Fetch-Site"))) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Cross-site request blocked");
            return;
        }
        chain.doFilter(request, response);
    }
}
