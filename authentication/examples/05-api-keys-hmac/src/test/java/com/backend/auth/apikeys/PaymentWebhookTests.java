package com.backend.auth.apikeys;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.backend.auth.apikeys.webhook.WebhookSigner;

/** The webhook endpoint end to end: signature over raw bytes, timestamp window, replay cache, idempotency. */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClockConfig.class)
class PaymentWebhookTests {

    private static final String SECRET = "whsec_demo_only_not_a_real_secret";   // DEMO secret from application.yml
    private static final String SIGNATURE_HEADER = "Payments-Signature";

    @Autowired
    MockMvc mvc;

    @Autowired
    MutableClock clock;

    @Test
    void validSignatureIsAccepted() throws Exception {
        String body = event();

        deliver(signNow(body), body)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.received").value(true))
                .andExpect(jsonPath("$.duplicate").value(false));
    }

    @Test
    void tamperedBodyIsRejected() throws Exception {
        String body = event();
        String signature = signNow(body);

        deliver(signature, body.replace("4200", "999999"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.title").value("Webhook rejected"));
    }

    @Test
    void signatureOlderThanTheToleranceIsRejected() throws Exception {
        String body = event();
        long sixMinutesAgo = clock.instant().minus(Duration.ofMinutes(6)).getEpochSecond();

        deliver(WebhookSigner.sign(SECRET, sixMinutesAgo, body), body).andExpect(status().isUnauthorized());
    }

    @Test
    void replayedDeliveryIsRejected() throws Exception {
        String body = event();
        String signature = signNow(body);

        deliver(signature, body).andExpect(status().isOk());
        clock.advance(Duration.ofSeconds(10));
        deliver(signature, body).andExpect(status().isUnauthorized());
    }

    @Test
    void providerRetryIsAcknowledgedButProcessedOnlyOnce() throws Exception {
        String body = event();
        deliver(signNow(body), body).andExpect(jsonPath("$.duplicate").value(false));

        // A real retry is signed again with a new timestamp: not a replay, but the same event id.
        clock.advance(Duration.ofSeconds(30));
        deliver(signNow(body), body)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.duplicate").value(true));
    }

    @Test
    void missingSignatureIsRejected() throws Exception {
        mvc.perform(post("/webhooks/payments").contentType(MediaType.APPLICATION_JSON).content(event()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void anApiKeyIsNotAWebhookSignature() throws Exception {
        String apiKey = AdminApi.createKey(mvc, "orders:read", "orders:write").key();

        mvc.perform(post("/webhooks/payments")
                        .header(HttpHeaders.AUTHORIZATION, AdminApi.bearer(apiKey))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void oversizedBodiesAreRefusedBeforeAnyHmacIsComputed() throws Exception {
        String body = "{\"id\":\"evt_big\",\"type\":\"payment.succeeded\",\"padding\":\"" + "x".repeat(64 * 1024) + "\"}";

        deliver(signNow(body), body).andExpect(status().isPayloadTooLarge());
    }

    private ResultActions deliver(String signature, String body) throws Exception {
        return mvc.perform(post("/webhooks/payments")
                .header(SIGNATURE_HEADER, signature)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private String signNow(String body) {
        return WebhookSigner.sign(SECRET, clock.instant().getEpochSecond(), body);
    }

    private static String event() {
        return "{\"id\":\"evt_" + UUID.randomUUID() + "\",\"type\":\"payment.succeeded\","
                + "\"data\":{\"amount\":4200,\"currency\":\"EUR\"}}";
    }
}
