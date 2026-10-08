package com.backend.auth.apikeys.apikey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.nio.charset.StandardCharsets;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

class ApiKeyHasherTests {

    private static final byte[] PEPPER = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    private static final String KEY = "ak_live_0000000000000000000000000000000000000000000000000";

    @Test
    void hashIsHmacSha256OfTheKeyUnderThePepper() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(PEPPER, "HmacSHA256"));

        assertThat(new ApiKeyHasher(PEPPER).hash(KEY))
                .hasSize(32)
                .isEqualTo(mac.doFinal(KEY.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void sameKeyAlwaysGivesTheSameHashSoItCanBeLookedUp() {
        ApiKeyHasher hasher = new ApiKeyHasher(PEPPER);
        assertThat(hasher.hash(KEY)).isEqualTo(hasher.hash(KEY));
    }

    @Test
    void anotherPepperGivesAnotherHash() {
        byte[] otherPepper = "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.US_ASCII);
        assertThat(new ApiKeyHasher(otherPepper).hash(KEY)).isNotEqualTo(new ApiKeyHasher(PEPPER).hash(KEY));
    }

    @Test
    void shortPeppersAreRefusedAtStartup() {
        assertThatIllegalArgumentException().isThrownBy(() -> new ApiKeyHasher(new byte[31]));
    }
}
