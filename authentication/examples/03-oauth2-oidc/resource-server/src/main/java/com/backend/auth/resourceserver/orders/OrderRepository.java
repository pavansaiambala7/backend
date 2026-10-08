package com.backend.auth.resourceserver.orders;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.stereotype.Repository;

/** DEMO data, in memory. Owners are the {@code sub} values the authorization server issues. */
@Repository
public class OrderRepository {

    private final List<Order> orders = List.of(
            new Order("A-1001", "alice", "Mechanical keyboard", new BigDecimal("129.00")),
            new Order("A-1002", "alice", "USB-C dock", new BigDecimal("89.50")),
            new Order("B-2001", "bob", "Noise-cancelling headphones", new BigDecimal("249.99")));

    public List<Order> findByOwner(String owner) {
        return orders.stream().filter(order -> order.owner().equals(owner)).toList();
    }
}
