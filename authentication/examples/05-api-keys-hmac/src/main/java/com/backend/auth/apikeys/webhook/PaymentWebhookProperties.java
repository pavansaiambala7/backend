package com.backend.auth.apikeys.webhook;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.unit.DataSize;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

/**
 * @param secrets     endpoint secrets shared with the payment provider; list two while rotating, the old one
 *                    removed once the provider signs only with the new one
 * @param tolerance   maximum difference between the signed timestamp and our clock, in either direction
 * @param maxBodySize larger bodies are refused before any HMAC is computed
 */
@Validated
@ConfigurationProperties("webhooks.payments")
public record PaymentWebhookProperties(
        @NotEmpty List<@Size(min = 32) String> secrets,
        @DefaultValue("5m") Duration tolerance,
        @DefaultValue("64KB") DataSize maxBodySize) {
}
