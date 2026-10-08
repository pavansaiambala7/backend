package com.backend.auth.mfa.otp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class Base32Test {

    /** RFC 4648, section 10. */
    @ParameterizedTest(name = "\"{0}\" -> {1}")
    @CsvSource({
            "'',       ''",
            "f,        MY======",
            "fo,       MZXQ====",
            "foo,      MZXW6===",
            "foob,     MZXW6YQ=",
            "fooba,    MZXW6YTB",
            "foobar,   MZXW6YTBOI======"
    })
    void rfc4648Vectors(String plain, String encoded) {
        byte[] bytes = plain.getBytes(StandardCharsets.US_ASCII);
        assertThat(Base32.encode(bytes)).isEqualTo(encoded);
        assertThat(Base32.decode(encoded)).isEqualTo(bytes);
    }

    @Test
    void a160BitSecretIs32CharactersWithoutPadding() {
        assertThat(Base32.encodeUnpadded(new byte[20])).hasSize(32).doesNotContain("=");
    }

    @Test
    void decodingIgnoresCaseSpacesAndDashes() {
        assertThat(Base32.decode("mzxw 6ytb-oi")).isEqualTo("foobar".getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void decodingRejectsCharactersOutsideTheAlphabet() {
        assertThatIllegalArgumentException().isThrownBy(() -> Base32.decode("MZXW1"));
        assertThatIllegalArgumentException().isThrownBy(() -> Base32.decode("MZXW€"));
    }

    @RepeatedTest(20)
    void randomBytesRoundTrip() {
        byte[] bytes = new byte[new SecureRandom().nextInt(64)];
        new SecureRandom().nextBytes(bytes);
        assertThat(Base32.decode(Base32.encodeUnpadded(bytes))).isEqualTo(bytes);
    }
}
