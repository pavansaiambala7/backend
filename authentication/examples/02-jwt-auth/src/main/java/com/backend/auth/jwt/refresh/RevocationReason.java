package com.backend.auth.jwt.refresh;

/** Why a refresh-token family was revoked. Stored for audit; never sent to the client. */
public enum RevocationReason {
    LOGOUT,
    /** An already-rotated token came back: two parties hold copies, so neither is trusted. */
    REUSE_DETECTED,
    ACCOUNT_DISABLED
}
