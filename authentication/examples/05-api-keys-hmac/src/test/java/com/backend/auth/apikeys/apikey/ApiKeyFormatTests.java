package com.backend.auth.apikeys.apikey;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

class ApiKeyFormatTests {

    private static final String BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private final ApiKeyFormat live = new ApiKeyFormat(KeyEnvironment.LIVE, new SecureRandom());

    @Test
    void keysHaveTheDocumentedShape() {
        String key = live.generate();

        assertThat(key).matches("ak_live_[0-9A-Za-z]{49}").hasSize(57).hasSize(live.keyLength());
        assertThat(live.lookupPrefix(key)).contains(key.substring(0, 16));
    }

    @Test
    void everyKeyIsDifferent() {
        Set<String> keys = new HashSet<>();
        for (int i = 0; i < 10_000; i++) {
            keys.add(live.generate());
        }
        assertThat(keys).hasSize(10_000);
    }

    @Test
    void the32SecretBytesAlwaysFitIn43Characters() {
        assertThat(new ApiKeyFormat(KeyEnvironment.LIVE, fixedBytes((byte) 0xFF)).generate())
                .startsWith("ak_live_" + largestSecret()).matches("ak_live_[0-9A-Za-z]{49}");
        assertThat(new ApiKeyFormat(KeyEnvironment.LIVE, fixedBytes((byte) 0x00)).generate())
                .startsWith("ak_live_" + "0".repeat(43));
    }

    @Test
    void anySingleCharacterTypoIsCaughtWithoutADatabaseLookup() {
        String key = live.generate();
        for (int position = "ak_live_".length(); position < key.length(); position++) {
            char original = key.charAt(position);
            char replacement = BASE62.charAt((BASE62.indexOf(original) + 1) % BASE62.length());
            String typo = key.substring(0, position) + replacement + key.substring(position + 1);

            assertThat(live.lookupPrefix(typo)).as("typo at position %d", position).isEmpty();
        }
    }

    @Test
    void keysFromAnotherEnvironmentAreNotAccepted() {
        String testKey = new ApiKeyFormat(KeyEnvironment.TEST, new SecureRandom()).generate();

        assertThat(testKey).startsWith("ak_test_");
        assertThat(live.lookupPrefix(testKey)).isEmpty();
    }

    @Test
    void garbageIsRejected() {
        String key = live.generate();
        assertThat(live.lookupPrefix(null)).isEmpty();
        assertThat(live.lookupPrefix("")).isEmpty();
        assertThat(live.lookupPrefix("ak_live_")).isEmpty();
        assertThat(live.lookupPrefix(key + "0")).isEmpty();
        assertThat(live.lookupPrefix(key.substring(0, 56) + "-")).isEmpty();
        assertThat(live.lookupPrefix(" " + key.substring(1))).isEmpty();
    }

    /** 2^256 - 1 (every byte 0xFF) in base62, computed independently of ApiKeyFormat. */
    private static String largestSecret() {
        BigInteger value = BigInteger.TWO.pow(256).subtract(BigInteger.ONE);
        StringBuilder digits = new StringBuilder();
        while (value.signum() > 0) {
            BigInteger[] quotientAndRemainder = value.divideAndRemainder(BigInteger.valueOf(62));
            digits.insert(0, BASE62.charAt(quotientAndRemainder[1].intValue()));
            value = quotientAndRemainder[0];
        }
        return "0".repeat(43 - digits.length()) + digits;
    }

    private static SecureRandom fixedBytes(byte value) {
        return new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                Arrays.fill(bytes, value);
            }
        };
    }
}
