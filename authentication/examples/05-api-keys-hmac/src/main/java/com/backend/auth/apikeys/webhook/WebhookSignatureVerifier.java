package com.backend.auth.apikeys.webhook;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import com.backend.auth.apikeys.crypto.HmacSha256;

/**
 * Verifies {@code t=<unix>,v1=<hex HMAC-SHA256(secret, t + "." + rawBody)>} signatures.
 *
 * <p>Order matters: parse, then the timestamp window (cheap), then the HMAC, and only for an authentic
 * message the replay cache. Recording unverified messages would let anyone fill the cache.
 */
public final class WebhookSignatureVerifier {

    public enum Outcome { VALID, MALFORMED_HEADER, TIMESTAMP_OUTSIDE_TOLERANCE, SIGNATURE_MISMATCH, REPLAYED }

    private final List<byte[]> secrets;
    private final Duration tolerance;
    private final Clock clock;
    private final ReplayCache replayCache;

    public WebhookSignatureVerifier(List<String> secrets, Duration tolerance, Clock clock, ReplayCache replayCache) {
        if (secrets.isEmpty()) {
            throw new IllegalArgumentException("At least one webhook secret is required");
        }
        this.secrets = secrets.stream().map(secret -> secret.getBytes(StandardCharsets.UTF_8)).toList();
        this.tolerance = tolerance;
        this.clock = clock;
        this.replayCache = replayCache;
    }

    /** @param rawBody the exact bytes received; re-serialized JSON would not match the signature */
    public Outcome verify(String signatureHeader, byte[] rawBody) {
        Optional<SignatureHeader> parsed = SignatureHeader.parse(signatureHeader);
        if (parsed.isEmpty()) {
            return Outcome.MALFORMED_HEADER;
        }
        long timestamp = parsed.get().timestamp();

        // The timestamp is inside the signed content, so it cannot be changed without breaking the HMAC.
        // The window limits how long a captured request stays usable; it also rejects timestamps in the future.
        long now = clock.instant().getEpochSecond();
        if (Math.abs(now - timestamp) > tolerance.toSeconds()) {
            return Outcome.TIMESTAMP_OUTSIDE_TOLERANCE;
        }

        byte[] signedPayload = signedPayload(timestamp, rawBody);
        boolean authentic = false;
        for (byte[] secret : secrets) {
            byte[] expected = HmacSha256.mac(secret, signedPayload);
            for (byte[] candidate : parsed.get().signatures()) {
                // Constant-time compare, and no early exit: every secret/candidate pair costs the same.
                authentic |= MessageDigest.isEqual(expected, candidate);
            }
        }
        if (!authentic) {
            return Outcome.SIGNATURE_MISMATCH;
        }

        // Key the replay cache on the signed content, not on the matching v1 value: during a rotation the
        // header carries two valid signatures, and dropping one of them must not turn a replay into a "new" message.
        String replayKey = HexFormat.of().formatHex(HmacSha256.sha256(signedPayload));
        // +1 s: the window check above works in whole seconds, the cache in exact instants.
        Instant rememberUntil = Instant.ofEpochSecond(timestamp).plus(tolerance).plusSeconds(1);
        if (!replayCache.firstSeen(replayKey, rememberUntil)) {
            return Outcome.REPLAYED;
        }
        return Outcome.VALID;
    }

    /** {@code timestamp + "." + rawBody}, as bytes: the body is never decoded, so no charset can alter it. */
    static byte[] signedPayload(long timestamp, byte[] rawBody) {
        byte[] prefix = (timestamp + ".").getBytes(StandardCharsets.US_ASCII);
        byte[] payload = new byte[prefix.length + rawBody.length];
        System.arraycopy(prefix, 0, payload, 0, prefix.length);
        System.arraycopy(rawBody, 0, payload, prefix.length, rawBody.length);
        return payload;
    }
}
