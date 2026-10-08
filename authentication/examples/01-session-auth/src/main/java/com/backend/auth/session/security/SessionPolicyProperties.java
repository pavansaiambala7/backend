package com.backend.auth.session.security;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Session rules that the servlet container does not provide by itself. (The idle timeout is the
 * container's {@code server.servlet.session.timeout}.)
 *
 * @param maximumPerUser  concurrent sessions per user; logging in on one more device expires the oldest
 * @param absoluteTimeout maximum session age counted from login, however active the session is
 */
@ConfigurationProperties("auth.session")
record SessionPolicyProperties(
        @DefaultValue("3") int maximumPerUser,
        @DefaultValue("8h") Duration absoluteTimeout) {
}
