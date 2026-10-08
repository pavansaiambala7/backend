package com.backend.auth.mfa.security;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.backend.auth.mfa.recovery.RecoveryCodeService;
import com.backend.auth.mfa.totp.TotpAuthenticator;

/**
 * Verifies a TOTP code or a recovery code and, on success, returns an {@code Authentication} carrying the matching
 * factor authority ({@code FACTOR_TOTP} or {@code FACTOR_RECOVERY_CODE}).
 */
public class SecondFactorAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(SecondFactorAuthenticationProvider.class);

    private final UserDetailsService users;
    private final SecondFactorThrottle throttle;
    private final TotpAuthenticator totp;
    private final RecoveryCodeService recoveryCodes;
    private final Clock clock;
    private final AccountStatusUserDetailsChecker accountStatus = new AccountStatusUserDetailsChecker();

    public SecondFactorAuthenticationProvider(UserDetailsService users, SecondFactorThrottle throttle,
                                              TotpAuthenticator totp, RecoveryCodeService recoveryCodes, Clock clock) {
        this.users = users;
        this.throttle = throttle;
        this.totp = totp;
        this.recoveryCodes = recoveryCodes;
        this.clock = clock;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        SecondFactorCodeToken request = (SecondFactorCodeToken) authentication;
        String username = request.getPrincipal();
        String code = request.getCredentials() == null ? "" : request.getCredentials();

        // Reload the user: an account disabled or locked since the password step must not complete its login.
        UserDetails user = users.loadUserByUsername(username);
        accountStatus.check(user);

        boolean verified = throttle.attempt(username, () -> switch (request.factor()) {
            case TOTP -> totp.verify(username, code);
            case RECOVERY_CODE -> recoveryCodes.redeem(username, code);
        });
        if (!verified) {
            log.info("Second factor {} failed for user {}", request.factor(), username);
            // One message for wrong, expired and reused codes: the caller learns nothing about which it was.
            throw new BadCredentialsException("Invalid or already used code");
        }
        log.info("Second factor {} succeeded for user {}", request.factor(), username);

        List<GrantedAuthority> authorities = new ArrayList<>(user.getAuthorities());
        authorities.add(FactorGrantedAuthority.withAuthority(request.factor().authority())
                .issuedAt(clock.instant())
                .build());
        SecondFactorAuthentication result = new SecondFactorAuthentication(user, authorities);
        result.setDetails(request.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SecondFactorCodeToken.class.isAssignableFrom(authentication);
    }
}
