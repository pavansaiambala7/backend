package com.backend.auth.jwt.api;

import java.time.Instant;
import java.util.UUID;

record Order(UUID id, String owner, String item, int quantity, Instant createdAt) {
}
