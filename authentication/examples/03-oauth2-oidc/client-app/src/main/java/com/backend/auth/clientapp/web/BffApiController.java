package com.backend.auth.clientapp.web;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import com.backend.auth.clientapp.orders.OrdersApiClient;

/**
 * The JSON API the frontend calls with its session cookie. Responses contain data, never tokens.
 */
@RestController
@RequestMapping("/api")
class BffApiController {

    private static final Logger log = LoggerFactory.getLogger(BffApiController.class);

    private final OrdersApiClient ordersApi;

    BffApiController(OrdersApiClient ordersApi) {
        this.ordersApi = ordersApi;
    }

    /** Who is signed in, taken from the validated ID token (and UserInfo). */
    @GetMapping("/me")
    CurrentUser me(@AuthenticationPrincipal OidcUser user) {
        return new CurrentUser(
                user.getIssuer().toString(),
                user.getSubject(),
                user.getFullName(),
                user.getPreferredUsername(),
                user.getAuthenticatedAt());
    }

    /** Proxies the orders API with the user's access token, attached here on the server. */
    @GetMapping("/orders")
    OrdersApiClient.MyOrders orders() {
        return ordersApi.myOrders();
    }

    /** No usable token any more (refresh token expired or rotated away, or the API rejected it). */
    @ExceptionHandler({ ClientAuthorizationException.class, HttpClientErrorException.Unauthorized.class })
    ProblemDetail reauthenticationRequired(RuntimeException ex) {
        log.debug("Access token unavailable or rejected; the user must sign in again", ex);
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Sign in again.");
        problem.setTitle("Reauthentication required");
        return problem;
    }

    /** Any other failure of the downstream API. Its error body is not passed through to the browser. */
    @ExceptionHandler(RestClientException.class)
    ProblemDetail ordersApiUnavailable(RestClientException ex) {
        if (ex instanceof RestClientResponseException response) {
            log.warn("Orders API answered {}", response.getStatusCode());
        }
        else {
            log.warn("Orders API call failed: {}", ex.getClass().getSimpleName());
        }
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_GATEWAY, "The orders service is unavailable.");
    }

    record CurrentUser(String issuer, String subject, String name, String preferredUsername, Instant authenticatedAt) {
    }
}
