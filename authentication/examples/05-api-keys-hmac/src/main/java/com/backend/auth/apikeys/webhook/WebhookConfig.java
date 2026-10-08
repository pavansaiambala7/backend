package com.backend.auth.apikeys.webhook;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
class WebhookConfig {

    @Bean
    ReplayCache webhookReplayCache(Clock clock) {
        return new InMemoryReplayCache(clock);
    }

    @Bean
    WebhookSignatureVerifier paymentWebhookVerifier(PaymentWebhookProperties properties, Clock clock, ReplayCache replayCache) {
        return new WebhookSignatureVerifier(properties.secrets(), properties.tolerance(), clock, replayCache);
    }
}
