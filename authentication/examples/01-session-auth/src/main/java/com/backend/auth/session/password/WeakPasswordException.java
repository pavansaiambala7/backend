package com.backend.auth.session.password;

/** A password was rejected; the message is safe to show to the user and explains why. */
public class WeakPasswordException extends RuntimeException {

    public WeakPasswordException(String userFacingReason) {
        super(userFacingReason);
    }
}
