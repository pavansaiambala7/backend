package com.backend.auth.clientapp.orders;

import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import com.backend.auth.clientapp.BffProperties;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Calls the resource server on behalf of the signed-in user. */
@Component
public class OrdersApiClient {

    private final RestClient ordersRestClient;
    private final String registrationId;

    OrdersApiClient(RestClient ordersRestClient, BffProperties properties) {
        this.ordersRestClient = ordersRestClient;
        this.registrationId = properties.registrationId();
    }

    public MyOrders myOrders() {
        return ordersRestClient.get()
                .uri("/api/orders")
                // Which client registration's token to attach; the user comes from the security context.
                .attributes(clientRegistrationId(registrationId))
                .retrieve()
                .body(MyOrders.class);
    }

    /** Tolerant reader: new fields in the API response do not break the BFF. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record MyOrders(String subject, List<Order> orders) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Order(String id, String item, BigDecimal total) {
    }
}
