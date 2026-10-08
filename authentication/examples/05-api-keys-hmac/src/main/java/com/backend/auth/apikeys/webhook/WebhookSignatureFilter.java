package com.backend.auth.apikeys.webhook;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import com.backend.auth.apikeys.security.ProblemWriter;
import com.backend.auth.apikeys.webhook.WebhookSignatureVerifier.Outcome;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Authenticates webhook deliveries by their HMAC signature. The signature is the authentication: a webhook
 * URL is public, so without this check anyone could post "payment succeeded".
 *
 * <p>It runs inside Spring Security rather than in the controller, so no handler under {@code /webhooks/**}
 * can forget it: requests that fail never reach MVC, and those that pass carry the
 * {@value #PAYMENTS_PROVIDER} authority that the authorization rules require.
 */
public final class WebhookSignatureFilter extends OncePerRequestFilter {

    public static final String SIGNATURE_HEADER = "Payments-Signature";
    public static final String PAYMENTS_PROVIDER = "WEBHOOK_PAYMENTS";

    private static final Logger log = LoggerFactory.getLogger(WebhookSignatureFilter.class);

    private final WebhookSignatureVerifier verifier;
    private final int maxBodyBytes;
    private final ProblemWriter problems;
    private final SecurityContextHolderStrategy contextHolder = SecurityContextHolder.getContextHolderStrategy();

    public WebhookSignatureFilter(WebhookSignatureVerifier verifier, int maxBodyBytes, ProblemWriter problems) {
        this.verifier = verifier;
        this.maxBodyBytes = maxBodyBytes;
        this.problems = problems;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // Bound the body before buffering it or computing any HMAC, so large posts cannot exhaust memory or CPU.
        if (request.getContentLengthLong() > maxBodyBytes) {
            problems.write(response, HttpStatus.CONTENT_TOO_LARGE, "Payload too large", "Webhook bodies are limited to " + maxBodyBytes + " bytes.");
            return;
        }
        byte[] body;
        try (InputStream in = request.getInputStream()) {
            body = in.readNBytes(maxBodyBytes + 1);
        }
        if (body.length > maxBodyBytes) {
            problems.write(response, HttpStatus.CONTENT_TOO_LARGE, "Payload too large", "Webhook bodies are limited to " + maxBodyBytes + " bytes.");
            return;
        }

        Outcome outcome = verifier.verify(request.getHeader(SIGNATURE_HEADER), body);
        if (outcome != Outcome.VALID) {
            // The reason goes to our logs only; the sender gets the same answer for every failure.
            log.warn("Webhook rejected: {} {} -> {}", request.getMethod(), request.getRequestURI(), outcome);
            problems.write(response, HttpStatus.UNAUTHORIZED, "Webhook rejected",
                    "Missing, invalid, expired or replayed " + SIGNATURE_HEADER + " header.");
            return;
        }

        SecurityContext context = contextHolder.createEmptyContext();
        context.setAuthentication(new PreAuthenticatedAuthenticationToken("payments-provider", null,
                List.of(new SimpleGrantedAuthority(PAYMENTS_PROVIDER))));
        contextHolder.setContext(context);
        chain.doFilter(new CachedBodyRequest(request, body), response);
    }
}
