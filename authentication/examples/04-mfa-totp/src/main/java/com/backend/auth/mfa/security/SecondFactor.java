package com.backend.auth.mfa.security;

/**
 * The second factors this application accepts after the password, each recorded in the session as its own
 * Spring Security factor authority ({@code FactorGrantedAuthority}).
 *
 * <p>A recovery code satisfies the same access rules as a TOTP code but gets a different authority, so the
 * application can tell the two apart: it warns after a recovery-code login, and a stricter rule could refuse
 * recovery codes for sensitive actions.
 */
public enum SecondFactor {

    /** A code from the user's authenticator app (RFC 6238). */
    TOTP("FACTOR_TOTP", "/login/totp"),

    /** One of the single-use codes issued at enrollment (NIST: a look-up secret). */
    RECOVERY_CODE("FACTOR_RECOVERY_CODE", "/login/recovery-code");

    private final String authority;
    private final String loginPage;

    SecondFactor(String authority, String loginPage) {
        this.authority = authority;
        this.loginPage = loginPage;
    }

    /** The factor authority added to the session's {@code Authentication} when this factor succeeds. */
    public String authority() {
        return authority;
    }

    /** The page that shows the form (GET) and the URL that processes it (POST). */
    public String loginPage() {
        return loginPage;
    }
}
