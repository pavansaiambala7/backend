package com.backend.auth.mfa.security;

import java.io.Serial;
import java.time.Duration;

import org.springframework.security.core.AuthenticationException;

/** Too many wrong second-factor codes for this account; the attempt was refused without checking the code. */
public class SecondFactorThrottledException extends AuthenticationException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final Duration retryAfter;

    public SecondFactorThrottledException(Duration retryAfter) {
        super("Too many failed second-factor attempts");
        this.retryAfter = retryAfter;
    }

    /** Whole seconds, rounded up, for the {@code Retry-After} header. */
    public long retryAfterSeconds() {
        return Math.max(1, (retryAfter.toMillis() + 999) / 1000);
    }
}
