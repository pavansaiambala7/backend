package com.backend.auth.apikeys.webhook;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import com.backend.auth.apikeys.MutableClock;
import com.backend.auth.apikeys.webhook.WebhookSignatureVerifier.Outcome;

class WebhookSignatureVerifierTests {

    private static final String SECRET = "whsec_demo_only_not_a_real_secret";
    private static final String NEW_SECRET = "whsec_demo_only_rotated_secret_number_2";
    private static final long T = 1_791_460_800L;              // 2026-10-08T12:00:00Z
    private static final String BODY = "{\"id\":\"evt_1Q2\",\"type\":\"invoice.paid\"}";
    private static final String HEX_64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(T));
    private final InMemoryReplayCache replayCache = new InMemoryReplayCache(clock);
    private final WebhookSignatureVerifier verifier = verifier(List.of(SECRET));

    @Test
    void knownAnswerComputedWithOpenssl() {
        // printf '%s' '1791460800.{"id":"evt_1Q2","type":"invoice.paid"}' | openssl dgst -sha256 -hmac 'whsec_demo_only_not_a_real_secret'
        String header = "t=1791460800,v1=b98bafc4c74dc1fef3596bd54ce51df3992dcfbf4d9ccbe621036193226fffb5";

        assertThat(WebhookSigner.sign(SECRET, T, BODY)).isEqualTo(header);
        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.VALID);
    }

    @Test
    void tamperedBodyIsRejected() {
        String header = WebhookSigner.sign(SECRET, T, BODY);

        assertThat(verifier.verify(header, bytes(BODY.replace("invoice.paid", "invoice.refunded"))))
                .isEqualTo(Outcome.SIGNATURE_MISMATCH);
    }

    @Test
    void reformattedJsonIsRejectedBecauseTheSignatureCoversRawBytes() {
        String header = WebhookSigner.sign(SECRET, T, BODY);

        assertThat(verifier.verify(header, bytes("{\"id\": \"evt_1Q2\", \"type\": \"invoice.paid\"}")))
                .isEqualTo(Outcome.SIGNATURE_MISMATCH);
    }

    @Test
    void timestampsOlderThanFiveMinutesAreRejected() {
        String header = WebhookSigner.sign(SECRET, T, BODY);
        clock.advance(Duration.ofMinutes(5).plusSeconds(1));

        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.TIMESTAMP_OUTSIDE_TOLERANCE);
    }

    @Test
    void timestampsExactlyAtTheToleranceAreAccepted() {
        String header = WebhookSigner.sign(SECRET, T, BODY);
        clock.advance(Duration.ofMinutes(5));

        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.VALID);
    }

    @Test
    void timestampsTooFarInTheFutureAreRejected() {
        long future = T + Duration.ofMinutes(5).toSeconds() + 1;

        assertThat(verifier.verify(WebhookSigner.sign(SECRET, future, BODY), bytes(BODY)))
                .isEqualTo(Outcome.TIMESTAMP_OUTSIDE_TOLERANCE);
    }

    @Test
    void refreshingAnOldTimestampBreaksTheSignature() {
        long old = T - Duration.ofHours(1).toSeconds();
        String capturedSignature = WebhookSigner.signature(SECRET, old, BODY);

        assertThat(verifier.verify("t=" + T + ",v1=" + capturedSignature, bytes(BODY)))
                .isEqualTo(Outcome.SIGNATURE_MISMATCH);
    }

    @Test
    void signatureWithAnotherSecretIsRejected() {
        assertThat(verifier.verify(WebhookSigner.sign("whsec_someone_elses_secret_value_xyz", T, BODY), bytes(BODY)))
                .isEqualTo(Outcome.SIGNATURE_MISMATCH);
    }

    @Test
    void theSameDeliveryIsAcceptedOnlyOnce() {
        String header = WebhookSigner.sign(SECRET, T, BODY);

        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.VALID);
        clock.advance(Duration.ofSeconds(30));
        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.REPLAYED);
    }

    @Test
    void replayAtTheVeryEndOfTheWindowIsStillCaught() {
        String header = WebhookSigner.sign(SECRET, T, BODY);
        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.VALID);

        clock.advance(Duration.ofMinutes(5).plusMillis(999));   // epoch second still inside the window

        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.REPLAYED);
    }

    @Test
    void anyOfSeveralSignaturesMayMatchWhileTheSenderRotatesItsSecret() {
        String header = "t=" + T + ",v1=" + WebhookSigner.signature(NEW_SECRET, T, BODY)
                + ",v1=" + WebhookSigner.signature(SECRET, T, BODY);

        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.VALID);
    }

    @Test
    void oldAndNewSecretsAreBothAcceptedDuringOurRotation() {
        WebhookSignatureVerifier rotating = verifier(List.of(NEW_SECRET, SECRET));

        assertThat(rotating.verify(WebhookSigner.sign(SECRET, T, BODY), bytes(BODY))).isEqualTo(Outcome.VALID);
        assertThat(rotating.verify(WebhookSigner.sign(NEW_SECRET, T, "{\"id\":\"evt_2\"}"), bytes("{\"id\":\"evt_2\"}")))
                .isEqualTo(Outcome.VALID);
    }

    @Test
    void droppingOneOfTwoSignaturesDoesNotDisguiseAReplay() {
        WebhookSignatureVerifier rotating = verifier(List.of(NEW_SECRET, SECRET));
        String oldSignature = WebhookSigner.signature(SECRET, T, BODY);
        String newSignature = WebhookSigner.signature(NEW_SECRET, T, BODY);

        assertThat(rotating.verify("t=" + T + ",v1=" + newSignature + ",v1=" + oldSignature, bytes(BODY)))
                .isEqualTo(Outcome.VALID);
        assertThat(rotating.verify("t=" + T + ",v1=" + oldSignature, bytes(BODY))).isEqualTo(Outcome.REPLAYED);
    }

    @Test
    void unknownSchemesAreIgnored() {
        String header = "t=" + T + ",v0=" + "b".repeat(64) + ",v1=" + WebhookSigner.signature(SECRET, T, BODY);

        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.VALID);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
        "garbage",
        "v1=" + HEX_64,                                   // no timestamp
        "t=1791460800",                                   // no signature
        "t=1791460800,v1=abc",                            // signature of the wrong length
        "t=abc,v1=" + HEX_64,                             // timestamp not a number
        "t=-1791460800,v1=" + HEX_64,                     // signed timestamp
        "t=1791460800,t=1791460801,v1=" + HEX_64,         // two timestamps: which one was signed?
        "t=1791460800,v1"                                 // element without '='
    })
    void malformedHeadersAreRejected(String header) {
        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.MALFORMED_HEADER);
    }

    @Test
    void oversizedHeadersAreRejectedBeforeParsing() {
        String header = "t=" + T + ",v1=" + WebhookSigner.signature(SECRET, T, BODY) + ",v0=" + "a".repeat(SignatureHeader.MAX_LENGTH);

        assertThat(verifier.verify(header, bytes(BODY))).isEqualTo(Outcome.MALFORMED_HEADER);
    }

    @Test
    void onlyVerifiedMessagesAreRecordedInTheReplayCache() {
        verifier.verify(WebhookSigner.sign("whsec_someone_elses_secret_value_xyz", T, BODY), bytes(BODY));
        verifier.verify("t=" + (T - 3600) + ",v1=" + HEX_64, bytes(BODY));
        assertThat(replayCache.size()).isZero();

        verifier.verify(WebhookSigner.sign(SECRET, T, BODY), bytes(BODY));
        assertThat(replayCache.size()).isOne();
    }

    private WebhookSignatureVerifier verifier(List<String> secrets) {
        return new WebhookSignatureVerifier(secrets, Duration.ofMinutes(5), clock, replayCache);
    }

    private static byte[] bytes(String body) {
        return body.getBytes(StandardCharsets.UTF_8);
    }
}
