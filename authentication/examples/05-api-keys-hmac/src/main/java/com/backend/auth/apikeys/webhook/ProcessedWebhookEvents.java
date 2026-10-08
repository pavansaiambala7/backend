package com.backend.auth.apikeys.webhook;

import java.time.Instant;
import java.time.ZoneOffset;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * Idempotency by event id. Providers retry until they get a 2xx, and each retry is freshly signed, so the
 * replay cache does not catch it: the primary key on {@code event_id} makes sure the event is acted on once.
 */
@Repository
class ProcessedWebhookEvents {

    private final JdbcClient jdbc;

    ProcessedWebhookEvents(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** @return true for the first delivery of this event id, false for a retry or duplicate */
    boolean recordFirstDelivery(String eventId, String eventType, Instant receivedAt) {
        try {
            // PostgreSQL: INSERT ... ON CONFLICT (event_id) DO NOTHING and check the row count instead.
            jdbc.sql("INSERT INTO processed_webhook_event (event_id, event_type, received_at) VALUES (:id, :type, :at)")
                    .param("id", eventId)
                    .param("type", eventType)
                    .param("at", receivedAt.atOffset(ZoneOffset.UTC))
                    .update();
            return true;
        }
        catch (DuplicateKeyException alreadyProcessed) {
            return false;
        }
    }
}
