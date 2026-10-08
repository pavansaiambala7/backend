package com.backend.auth.mfa.otp;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/** The drift window: which time steps a submitted code may come from. */
class TotpWindowTest {

    private static final byte[] KEY = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final Totp TOTP = Totp.authenticatorAppDefaults();
    private static final Instant NOW = Instant.ofEpochSecond(1_234_567_890);
    private static final long STEP = TOTP.timeStep(NOW);

    @Test
    void currentCodeMatchesTheCurrentStep() {
        assertThat(TOTP.matchingStep(KEY, TOTP.codeAt(KEY, STEP), NOW, 1)).hasValue(STEP);
    }

    @Test
    void oneStepOfDriftIsToleratedInEitherDirection() {
        assertThat(TOTP.matchingStep(KEY, TOTP.codeAt(KEY, STEP - 1), NOW, 1)).hasValue(STEP - 1);
        assertThat(TOTP.matchingStep(KEY, TOTP.codeAt(KEY, STEP + 1), NOW, 1)).hasValue(STEP + 1);
    }

    @Test
    void codesTwoStepsAwayAreRejected() {
        assertThat(TOTP.matchingStep(KEY, TOTP.codeAt(KEY, STEP - 2), NOW, 1)).isEmpty();
        assertThat(TOTP.matchingStep(KEY, TOTP.codeAt(KEY, STEP + 2), NOW, 1)).isEmpty();
    }

    @Test
    void withoutDriftOnlyTheCurrentStepIsAccepted() {
        assertThat(TOTP.matchingStep(KEY, TOTP.codeAt(KEY, STEP), NOW, 0)).hasValue(STEP);
        assertThat(TOTP.matchingStep(KEY, TOTP.codeAt(KEY, STEP - 1), NOW, 0)).isEmpty();
    }

    @Test
    void stepBoundariesFollowTheThirtySecondPeriod() {
        Instant startOfStep = Instant.ofEpochSecond(STEP * 30);
        assertThat(TOTP.timeStep(startOfStep)).isEqualTo(STEP);
        assertThat(TOTP.timeStep(startOfStep.plusSeconds(29))).isEqualTo(STEP);
        assertThat(TOTP.timeStep(startOfStep.plusSeconds(30))).isEqualTo(STEP + 1);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "12345", "1234567", "12345a", "١٢٣٤٥٦", "+12345"})
    void malformedCodesNeverMatch(String code) {
        assertThat(TOTP.matchingStep(KEY, code, NOW, 1)).isEmpty();
    }
}
