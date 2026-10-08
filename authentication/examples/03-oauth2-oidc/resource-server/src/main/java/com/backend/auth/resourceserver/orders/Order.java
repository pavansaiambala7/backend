package com.backend.auth.resourceserver.orders;

import java.math.BigDecimal;

public record Order(String id, String owner, String item, BigDecimal total) {
}
