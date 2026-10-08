package com.backend.auth.apikeys;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Replaces the application clock in every Spring test. All test classes import it, so they share one cached
 * application context. Tests only ever move time forward and work relative to {@code clock.instant()}.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestClockConfig {

    @Bean
    @Primary
    MutableClock testClock() {
        return new MutableClock(Instant.now().truncatedTo(ChronoUnit.SECONDS));
    }
}
