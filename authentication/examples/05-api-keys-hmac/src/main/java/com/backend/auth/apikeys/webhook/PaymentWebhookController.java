package com.backend.auth.apikeys.webhook;

import java.time.Clock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

/**
 * Receives payment events. By the time a request gets here, {@link WebhookSignatureFilter} has verified the
 * signature over the raw bytes; this method only deals with retries and hands the event on.
 */
@RestController
class PaymentWebhookController {

    private static final Logger log = LoggerFactory.getLogger(PaymentWebhookController.class);

    record Receipt(boolean received, boolean duplicate) {
    }

    private final ProcessedWebhookEvents processedEvents;
    private final Clock clock;

    PaymentWebhookController(ProcessedWebhookEvents processedEvents, Clock clock) {
        this.processedEvents = processedEvents;
        this.clock = clock;
    }

    @PostMapping(path = "/webhooks/payments", consumes = MediaType.APPLICATION_JSON_VALUE)
    Receipt receive(@Valid @RequestBody PaymentEvent event) {
        boolean first = processedEvents.recordFirstDelivery(event.id(), event.type(), clock.instant());
        if (first) {
            // Real systems enqueue here and answer fast; slow handlers cause provider timeouts and more retries.
            // For money movements, re-fetch the object from the provider's API instead of trusting the payload.
            log.info("Payment event accepted: id={} type={}", event.id(), event.type());
        }
        else {
            log.info("Payment event already processed, acknowledging retry: id={}", event.id());
        }
        // 200 for duplicates too: an error would only make the provider retry again.
        return new Receipt(true, !first);
    }
}
