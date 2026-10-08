package com.backend.auth.jwt.api;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

/**
 * Scope checks (orders:read, orders:write) happen in SecurityConfig. Scopes say what kind of thing a
 * token may do; which orders it may touch is still decided here, by the token's subject (object-level
 * authorization).
 */
@RestController
@RequestMapping("/api/orders")
class OrderController {

    // DEMO ONLY: in-memory storage, keyed by owner.
    private final Map<String, List<Order>> ordersByOwner = new ConcurrentHashMap<>();
    private final Clock clock;

    OrderController(Clock clock) {
        this.clock = clock;
    }

    @GetMapping
    List<Order> myOrders(@AuthenticationPrincipal Jwt jwt) {
        return List.copyOf(ordersByOwner.getOrDefault(jwt.getSubject(), List.of()));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    Order create(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody NewOrder request) {
        Order order = new Order(UUID.randomUUID(), jwt.getSubject(), request.item(), request.quantity(), clock.instant());
        ordersByOwner.computeIfAbsent(jwt.getSubject(), owner -> new CopyOnWriteArrayList<>()).add(order);
        return order;
    }
}
