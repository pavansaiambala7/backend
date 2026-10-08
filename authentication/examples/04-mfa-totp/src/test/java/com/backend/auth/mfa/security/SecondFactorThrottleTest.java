package com.backend.auth.mfa.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.backend.auth.mfa.MutableClock;

class SecondFactorThrottleTest {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-08T10:00:00Z"));
    private final SecondFactorThrottle throttle = new SecondFactorThrottle(
            new SecondFactorProperties(Duration.ofMinutes(5), 5, Duration.ofSeconds(30), Duration.ofMinutes(15)), clock);

    @Test
    void afterFiveFailuresEvenTheCorrectCodeIsRefusedWithoutBeingChecked() {
        failTimes("alice", 5);
        AtomicInteger checks = new AtomicInteger();

        assertThatThrownBy(() -> throttle.attempt("alice", () -> checks.incrementAndGet() > 0))
                .isInstanceOfSatisfying(SecondFactorThrottledException.class,
                        e -> assertThat(e.retryAfterSeconds()).isEqualTo(30));
        assertThat(checks).hasValue(0);
    }

    @Test
    void theBlockEndsAndEachFurtherFailureDoublesIt() {
        failTimes("alice", 5);

        clock.advance(Duration.ofSeconds(30));
        assertThat(throttle.attempt("alice", () -> false)).isFalse();      // 6th failure
        assertBlockedFor("alice", 60);

        clock.advance(Duration.ofSeconds(60));
        assertThat(throttle.attempt("alice", () -> false)).isFalse();      // 7th failure
        assertBlockedFor("alice", 120);
    }

    @Test
    void blocksAreCappedAtTheMaximum() {
        failTimes("alice", 5);
        for (int i = 0; i < 10; i++) {
            clock.advance(Duration.ofHours(1));
            throttle.attempt("alice", () -> false);
        }
        assertBlockedFor("alice", 15 * 60);
    }

    @Test
    void successResetsTheCount() {
        failTimes("alice", 4);
        assertThat(throttle.attempt("alice", () -> true)).isTrue();

        failTimes("alice", 4);
        assertThat(throttle.attempt("alice", () -> true)).isTrue();   // not blocked: the count restarted
    }

    @Test
    void accountsAreThrottledIndependently() {
        failTimes("alice", 5);

        assertThat(throttle.attempt("bob", () -> true)).isTrue();
    }

    private void failTimes(String username, int times) {
        for (int i = 0; i < times; i++) {
            assertThat(throttle.attempt(username, () -> false)).isFalse();
        }
    }

    private void assertBlockedFor(String username, long seconds) {
        assertThatThrownBy(() -> throttle.attempt(username, () -> true))
                .isInstanceOfSatisfying(SecondFactorThrottledException.class,
                        e -> assertThat(e.retryAfterSeconds()).isEqualTo(seconds));
    }
}
