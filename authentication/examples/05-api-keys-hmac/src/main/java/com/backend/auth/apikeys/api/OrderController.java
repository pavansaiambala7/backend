package com.backend.auth.apikeys.api;

import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

/**
 * The protected business API. Scope checks happen in SecurityConfig ({@code orders:read} / {@code orders:write});
 * here the owner from the key decides whose orders are visible. An in-memory map stands in for a database.
 */
@RestController
@RequestMapping("/v1/orders")
class OrderController {

    private final Map<String, List<Order>> ordersByOwner = new ConcurrentHashMap<>();
    private final Clock clock;

    OrderController(Clock clock) {
        this.clock = clock;
    }

    @GetMapping
    List<Order> list(Authentication authentication) {
        return List.copyOf(ordersFor(authentication.getName()));
    }

    @PostMapping
    ResponseEntity<Order> create(Authentication authentication, @Valid @RequestBody NewOrder request) {
        Order order = new Order(UUID.randomUUID(), authentication.getName(), request.item(), request.quantity(), clock.instant());
        ordersFor(order.owner()).add(order);
        return ResponseEntity.created(URI.create("/v1/orders/" + order.id())).body(order);
    }

    private List<Order> ordersFor(String owner) {
        return ordersByOwner.computeIfAbsent(owner, ignored -> new CopyOnWriteArrayList<>());
    }
}
