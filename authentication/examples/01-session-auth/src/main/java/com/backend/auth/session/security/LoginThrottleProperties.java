package com.backend.auth.session.security;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Thresholds for the three login-failure counters. Once a counter reaches its threshold, the key is
 * blocked for {@code initialBlock}; every further failure after a block doubles it, up to {@code maxBlock}.
 *
 * @param maxFailuresPerUserAndIp one client guessing one account (classic brute force)
 * @param maxFailuresPerUser      one account attacked from many IPs (distributed brute force)
 * @param maxFailuresPerIp        one IP trying many accounts (password spraying)
 * @param forgetAfter             a counter with no new failures for this long starts again from zero
 */
@ConfigurationProperties("auth.login-throttle")
record LoginThrottleProperties(
        @DefaultValue("5") int maxFailuresPerUserAndIp,
        @DefaultValue("20") int maxFailuresPerUser,
        @DefaultValue("50") int maxFailuresPerIp,
        @DefaultValue("30s") Duration initialBlock,
        @DefaultValue("15m") Duration maxBlock,
        @DefaultValue("1h") Duration forgetAfter) {
}
