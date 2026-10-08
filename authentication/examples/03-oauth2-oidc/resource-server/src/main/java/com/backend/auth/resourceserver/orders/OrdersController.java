package com.backend.auth.resourceserver.orders;

import java.util.List;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class OrdersController {

    private final OrderRepository orders;

    OrdersController(OrderRepository orders) {
        this.orders = orders;
    }

    /**
     * The caller's orders. Whose orders they are comes from the validated token's {@code sub}, never
     * from a request parameter, so one user cannot ask for another user's data (no IDOR).
     * For a client credentials token, {@code sub} is the client ID, which owns no orders here.
     */
    @GetMapping("/api/orders")
    OrdersResponse myOrders(@AuthenticationPrincipal Jwt token) {
        return new OrdersResponse(
                token.getSubject(),
                token.getClaimAsString("client_id"),
                orders.findByOwner(token.getSubject()));
    }

    record OrdersResponse(String subject, String clientId, List<Order> orders) {
    }
}
