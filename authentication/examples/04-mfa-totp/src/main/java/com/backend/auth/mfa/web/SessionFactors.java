package com.backend.auth.mfa.web;

import java.time.Instant;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import com.backend.auth.mfa.security.SecondFactor;

/** Reads the factor authorities of the current session's {@link Authentication}. */
final class SessionFactors {

    /** One completed factor, e.g. {@code FACTOR_PASSWORD} at 10:15:02Z. */
    record Factor(String authority, Instant issuedAt) {
    }

    private SessionFactors() {
    }

    static List<Factor> of(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .filter(FactorGrantedAuthority.class::isInstance)
                .map(FactorGrantedAuthority.class::cast)
                .map(factor -> new Factor(factor.getAuthority(), factor.getIssuedAt()))
                .toList();
    }

    static boolean has(Authentication authentication, SecondFactor factor) {
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> factor.authority().equals(authority.getAuthority()));
    }

    static boolean hasSecondFactor(Authentication authentication) {
        return has(authentication, SecondFactor.TOTP) || has(authentication, SecondFactor.RECOVERY_CODE);
    }
}
