package com.backend.auth.apikeys.webhook;

import java.util.Map;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** The parts of a provider event this endpoint needs; unknown fields are ignored. */
public record PaymentEvent(
        @NotBlank @Size(max = 255) String id,
        @NotBlank @Size(max = 100) String type,
        Map<String, Object> data) {
}
