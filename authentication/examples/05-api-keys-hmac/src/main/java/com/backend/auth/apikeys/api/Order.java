package com.backend.auth.apikeys.api;

import java.time.Instant;
import java.util.UUID;

public record Order(UUID id, String owner, String item, int quantity, Instant createdAt) {
}
