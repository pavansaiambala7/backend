package com.backend.auth.apikeys.webhook;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import com.backend.auth.apikeys.crypto.HmacSha256;

/**
 * A parsed {@code t=<unix seconds>,v1=<hex HMAC-SHA256>[,v1=...]} header (the Stripe format). Several
 * {@code v1} values appear while the sender rotates its secret; unknown schemes such as {@code v0} are ignored.
 */
record SignatureHeader(long timestamp, List<byte[]> signatures) {

    static final int MAX_LENGTH = 2048;

    private static final Pattern TIMESTAMP = Pattern.compile("\\d{1,12}");          // no sign, no overflow
    private static final Pattern SIGNATURE = Pattern.compile("[0-9a-fA-F]{" + 2 * HmacSha256.LENGTH_BYTES + "}");

    /** Empty when the header is missing, oversized, has no or several timestamps, or has no usable v1 value. */
    static Optional<SignatureHeader> parse(String header) {
        if (header == null || header.isBlank() || header.length() > MAX_LENGTH) {
            return Optional.empty();
        }
        Long timestamp = null;
        List<byte[]> signatures = new ArrayList<>();
        for (String element : header.split(",")) {
            String[] pair = element.strip().split("=", 2);
            if (pair.length != 2) {
                return Optional.empty();
            }
            String name = pair[0];
            String value = pair[1];
            if (name.equals("t")) {
                // Two timestamps would leave it unclear which one was signed: refuse rather than pick one.
                if (timestamp != null || !TIMESTAMP.matcher(value).matches()) {
                    return Optional.empty();
                }
                timestamp = Long.parseLong(value);
            }
            else if (name.equals("v1") && SIGNATURE.matcher(value).matches()) {
                signatures.add(HexFormat.of().parseHex(value));
            }
        }
        if (timestamp == null || signatures.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new SignatureHeader(timestamp, List.copyOf(signatures)));
    }
}
