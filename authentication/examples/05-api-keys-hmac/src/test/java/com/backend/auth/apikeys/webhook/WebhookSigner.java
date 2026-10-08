package com.backend.auth.apikeys.webhook;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The sender's side of the scheme, as a payment provider would implement it. Written independently of the
 * production helpers (plain javax.crypto), so a bug shared by signer and verifier cannot make tests pass;
 * the known-answer test in WebhookSignatureVerifierTests pins both to an openssl-computed value.
 */
public final class WebhookSigner {

    private WebhookSigner() {
    }

    /** @return a {@code Payments-Signature} header value: {@code t=<timestamp>,v1=<hex HMAC>} */
    public static String sign(String secret, long timestamp, String body) {
        return "t=" + timestamp + ",v1=" + signature(secret, timestamp, body);
    }

    public static String signature(String secret, long timestamp, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] signed = mac.doFinal((timestamp + "." + body).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(signed);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
