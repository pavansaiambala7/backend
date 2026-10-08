package com.backend.auth.mfa.otp;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * The test vectors from RFC 6238, Appendix B: proof that {@link Totp} and {@link Hotp} implement the RFC.
 * The RFC uses 8-digit codes for the vectors; the application uses the same algorithm with 6 digits.
 */
class TotpRfc6238Test {

    // The seeds from the RFC's reference implementation: "1234567890" repeated to 20, 32 and 64 bytes.
    private static final byte[] SEED_SHA1 = ascii("12345678901234567890");
    private static final byte[] SEED_SHA256 = ascii("12345678901234567890123456789012");
    private static final byte[] SEED_SHA512 = ascii("1234567890123456789012345678901234567890123456789012345678901234");

    @ParameterizedTest(name = "SHA1 at {0}: T={1}, TOTP={2}")
    @CsvSource({
            "59,          0000000000000001, 94287082",
            "1111111109,  00000000023523EC, 07081804",
            "1111111111,  00000000023523ED, 14050471",
            "1234567890,  000000000273EF07, 89005924",
            "2000000000,  0000000003F940AA, 69279037",
            "20000000000, 0000000027BC86AA, 65353130"
    })
    void sha1Vectors(long unixTime, String timeStepHex, String expected) {
        Totp totp = new Totp(HmacAlgorithm.SHA1, 8, Duration.ofSeconds(30));
        Instant time = Instant.ofEpochSecond(unixTime);

        assertThat(totp.timeStep(time)).isEqualTo(Long.parseLong(timeStepHex, 16));
        assertThat(totp.codeAt(SEED_SHA1, time)).isEqualTo(expected);
    }

    @ParameterizedTest(name = "SHA256 at {0}: TOTP={1}")
    @CsvSource({
            "59,          46119246",
            "1111111109,  68084774",
            "1111111111,  67062674",
            "1234567890,  91819424",
            "2000000000,  90698825",
            "20000000000, 77737706"
    })
    void sha256Vectors(long unixTime, String expected) {
        Totp totp = new Totp(HmacAlgorithm.SHA256, 8, Duration.ofSeconds(30));
        assertThat(totp.codeAt(SEED_SHA256, Instant.ofEpochSecond(unixTime))).isEqualTo(expected);
    }

    @ParameterizedTest(name = "SHA512 at {0}: TOTP={1}")
    @CsvSource({
            "59,          90693936",
            "1111111109,  25091201",
            "1111111111,  99943326",
            "1234567890,  93441116",
            "2000000000,  38618901",
            "20000000000, 47863826"
    })
    void sha512Vectors(long unixTime, String expected) {
        Totp totp = new Totp(HmacAlgorithm.SHA512, 8, Duration.ofSeconds(30));
        assertThat(totp.codeAt(SEED_SHA512, Instant.ofEpochSecond(unixTime))).isEqualTo(expected);
    }

    /** RFC 4226, Appendix D: HOTP values for counters 0-9 (the function TOTP is built on). */
    @ParameterizedTest(name = "HOTP counter {0} = {1}")
    @CsvSource({
            "0, 755224", "1, 287082", "2, 359152", "3, 969429", "4, 338314",
            "5, 254676", "6, 287922", "7, 162583", "8, 399871", "9, 520489"
    })
    void hotpVectorsFromRfc4226(long counter, String expected) {
        assertThat(Hotp.generate(SEED_SHA1, counter, 6, HmacAlgorithm.SHA1)).isEqualTo(expected);
    }

    /** The 6-digit app code is the last six digits of the 8-digit value: same truncation, smaller modulus. */
    @ParameterizedTest(name = "6-digit code at {0} = {1}")
    @CsvSource({"59, 287082", "1111111109, 081804", "1234567890, 005924"})
    void sixDigitCodesKeepLeadingZeros(long unixTime, String expected) {
        assertThat(Totp.authenticatorAppDefaults().codeAt(SEED_SHA1, Instant.ofEpochSecond(unixTime))).isEqualTo(expected);
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
