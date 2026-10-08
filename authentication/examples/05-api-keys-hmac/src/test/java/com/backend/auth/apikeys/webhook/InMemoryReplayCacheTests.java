package com.backend.auth.apikeys.webhook;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import com.backend.auth.apikeys.MutableClock;

class InMemoryReplayCacheTests {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-08T12:00:00Z"));
    private final InMemoryReplayCache cache = new InMemoryReplayCache(clock);

    @Test
    void aKeyIsFirstSeenOnlyOnce() {
        Instant until = clock.instant().plus(Duration.ofMinutes(5));

        assertThat(cache.firstSeen("message-1", until)).isTrue();
        assertThat(cache.firstSeen("message-1", until)).isFalse();
        assertThat(cache.firstSeen("message-2", until)).isTrue();
    }

    @Test
    void expiredEntriesAreForgottenSoMemoryStaysBounded() {
        cache.firstSeen("message-1", clock.instant().plus(Duration.ofMinutes(5)));
        clock.advance(Duration.ofMinutes(5));

        assertThat(cache.firstSeen("message-2", clock.instant().plus(Duration.ofMinutes(5)))).isTrue();
        assertThat(cache.size()).isOne();
    }

    @Test
    void ofManyConcurrentIdenticalDeliveriesExactlyOneWins() throws Exception {
        Instant until = clock.instant().plus(Duration.ofMinutes(5));
        Callable<Boolean> deliver = () -> cache.firstSeen("same-message", until);

        try (ExecutorService pool = Executors.newFixedThreadPool(16)) {
            var results = pool.invokeAll(IntStream.range(0, 64).mapToObj(i -> deliver).toList());
            long winners = 0;
            for (Future<Boolean> result : results) {
                winners += result.get() ? 1 : 0;
            }
            assertThat(winners).isOne();
        }
    }
}
