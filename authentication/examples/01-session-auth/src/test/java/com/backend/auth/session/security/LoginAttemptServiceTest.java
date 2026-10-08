package com.backend.auth.session.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit tests for the throttling rules, with a controllable clock instead of sleeps. */
class LoginAttemptServiceTest {

    private static final String ALICE = "alice@example.com";
    private static final String ATTACKER_IP = "203.0.113.7";
    private static final String OTHER_IP = "198.51.100.20";

    private final MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    private LoginAttemptService attempts;

    @BeforeEach
    void setUp() {
        LoginThrottleProperties properties = new LoginThrottleProperties(
                3,                          // per user + IP
                6,                          // per user
                10,                         // per IP
                Duration.ofSeconds(30),     // first block
                Duration.ofMinutes(5),      // longest block
                Duration.ofHours(1));       // forget idle counters
        attempts = new LoginAttemptService(properties, clock);
    }

    @Test
    void blocksAUsernameAndIpPairAfterTheThreshold() {
        fail(ALICE, ATTACKER_IP, 2);
        assertThat(attempts.retryAfter(ALICE, ATTACKER_IP)).isEmpty();

        fail(ALICE, ATTACKER_IP, 1);

        assertThat(attempts.retryAfter(ALICE, ATTACKER_IP)).contains(Duration.ofSeconds(30));
        // The real user on another network is not locked out by the attacker.
        assertThat(attempts.retryAfter(ALICE, OTHER_IP)).isEmpty();
    }

    @Test
    void blockExpiresAndTheNextFailureDoublesIt() {
        fail(ALICE, ATTACKER_IP, 3);

        clock.advance(Duration.ofSeconds(30));
        assertThat(attempts.retryAfter(ALICE, ATTACKER_IP)).isEmpty();

        fail(ALICE, ATTACKER_IP, 1);
        assertThat(attempts.retryAfter(ALICE, ATTACKER_IP)).contains(Duration.ofSeconds(60));
    }

    @Test
    void blockDurationIsCapped() {
        for (int i = 0; i < 12; i++) {
            fail(ALICE, ATTACKER_IP, 1);
            attempts.retryAfter(ALICE, ATTACKER_IP).ifPresent(clock::advance);
        }
        fail(ALICE, ATTACKER_IP, 1);

        assertThat(attempts.retryAfter(ALICE, ATTACKER_IP)).contains(Duration.ofMinutes(5));
    }

    @Test
    void accountIsThrottledAcrossManyIps() {
        for (int i = 1; i <= 6; i++) {
            fail(ALICE, "192.0.2." + i, 1);
        }

        assertThat(attempts.retryAfter(ALICE, "192.0.2.99")).isPresent();
    }

    @Test
    void ipIsThrottledWhenSprayingManyAccounts() {
        for (int i = 1; i <= 10; i++) {
            fail("user" + i + "@example.com", ATTACKER_IP, 1);
        }

        assertThat(attempts.retryAfter("someone-new@example.com", ATTACKER_IP)).isPresent();
        assertThat(attempts.retryAfter("someone-new@example.com", OTHER_IP)).isEmpty();
    }

    @Test
    void unknownAndKnownUsernamesAreTreatedIdentically() {
        fail("does-not-exist@example.com", ATTACKER_IP, 3);
        fail(ALICE, OTHER_IP, 3);

        assertThat(attempts.retryAfter("does-not-exist@example.com", ATTACKER_IP))
                .isEqualTo(attempts.retryAfter(ALICE, OTHER_IP));
    }

    @Test
    void usernameIsNormalizedLikeTheAccountLookup() {
        fail("  Alice@Example.COM ", ATTACKER_IP, 3);

        assertThat(attempts.retryAfter(ALICE, ATTACKER_IP)).isPresent();
    }

    @Test
    void successResetsTheAccountCountersButNotTheIpCounter() {
        for (int i = 1; i <= 9; i++) {
            fail("user" + i + "@example.com", ATTACKER_IP, 1);
        }
        fail(ALICE, ATTACKER_IP, 2);   // 11 failures from this IP: blocked
        clock.advance(Duration.ofMinutes(10));

        attempts.recordSuccess(ALICE, ATTACKER_IP);
        fail("user10@example.com", ATTACKER_IP, 1);

        // An attacker cannot wipe their IP's history by logging into an account they own.
        assertThat(attempts.retryAfter("user11@example.com", ATTACKER_IP)).isPresent();
    }

    @Test
    void successResetsTheUserAndIpCounter() {
        fail(ALICE, ATTACKER_IP, 2);
        attempts.recordSuccess(ALICE, ATTACKER_IP);
        fail(ALICE, ATTACKER_IP, 2);

        assertThat(attempts.retryAfter(ALICE, ATTACKER_IP)).isEmpty();
    }

    @Test
    void idleCountersAreForgotten() {
        fail(ALICE, ATTACKER_IP, 2);
        clock.advance(Duration.ofHours(1));

        fail(ALICE, ATTACKER_IP, 2);

        assertThat(attempts.retryAfter(ALICE, ATTACKER_IP)).isEmpty();
    }

    private void fail(String username, String ip, int times) {
        for (int i = 0; i < times; i++) {
            attempts.recordFailure(username, ip);
        }
    }
}
