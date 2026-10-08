package com.backend.auth.mfa.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;

class SecretEncryptorTest {

    private static final String KEY_1 = Base64.getEncoder().encodeToString(new byte[32]);
    private static final String KEY_2 = Base64.getEncoder().encodeToString("an-other-32-byte-test-key-value!".getBytes(StandardCharsets.US_ASCII));
    private static final byte[] SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    private final SecretEncryptor encryptor = new SecretEncryptor(new EncryptionProperties("k1", Map.of("k1", KEY_1)));

    @Test
    void roundTripsAndNamesTheKey() {
        String stored = encryptor.encrypt(SECRET, "alice");

        assertThat(stored).startsWith("k1:");
        assertThat(encryptor.decrypt(stored, "alice")).isEqualTo(SECRET);
    }

    @Test
    void usesAFreshNonceEveryTime() {
        assertThat(encryptor.encrypt(SECRET, "alice")).isNotEqualTo(encryptor.encrypt(SECRET, "alice"));
    }

    @Test
    void aCiphertextCopiedToAnotherUserDoesNotDecrypt() {
        String alicesSecret = encryptor.encrypt(SECRET, "alice");

        assertThatIllegalStateException().isThrownBy(() -> encryptor.decrypt(alicesSecret, "mallory"));
    }

    @Test
    void anyModificationIsDetected() {
        String stored = encryptor.encrypt(SECRET, "alice");
        byte[] data = Base64.getDecoder().decode(stored.substring(3));
        data[data.length - 1] ^= 1;
        String tampered = "k1:" + Base64.getEncoder().encodeToString(data);

        assertThatIllegalStateException().isThrownBy(() -> encryptor.decrypt(tampered, "alice"));
    }

    @Test
    void afterRotationOldCiphertextsStillDecryptAndNewOnesUseTheNewKey() {
        String storedWithOldKey = encryptor.encrypt(SECRET, "alice");
        SecretEncryptor rotated = new SecretEncryptor(new EncryptionProperties("k2", Map.of("k1", KEY_1, "k2", KEY_2)));

        assertThat(rotated.decrypt(storedWithOldKey, "alice")).isEqualTo(SECRET);
        assertThat(rotated.encrypt(SECRET, "alice")).startsWith("k2:");
    }

    @Test
    void unknownKeyIdFails() {
        String stored = encryptor.encrypt(SECRET, "alice");
        SecretEncryptor withoutOldKey = new SecretEncryptor(new EncryptionProperties("k2", Map.of("k2", KEY_2)));

        assertThatIllegalStateException().isThrownBy(() -> withoutOldKey.decrypt(stored, "alice"));
    }

    @Test
    void refusesKeysThatAreNot256Bits() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);

        assertThatIllegalStateException()
                .isThrownBy(() -> new SecretEncryptor(new EncryptionProperties("k1", Map.of("k1", shortKey))));
    }
}
