package com.backend.auth.jwt.web;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.backend.auth.jwt.refresh.RefreshResult;
import com.backend.auth.jwt.refresh.RefreshTokenService;
import com.backend.auth.jwt.refresh.RevocationReason;
import com.backend.auth.jwt.token.AccessTokenService;

/** Login, refresh and logout: pairs a short-lived access token with a rotating refresh token. */
@Service
class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService users;
    private final AccessTokenService accessTokens;
    private final RefreshTokenService refreshTokens;

    AuthService(AuthenticationManager authenticationManager, UserDetailsService users,
                AccessTokenService accessTokens, RefreshTokenService refreshTokens) {
        this.authenticationManager = authenticationManager;
        this.users = users;
        this.accessTokens = accessTokens;
        this.refreshTokens = refreshTokens;
    }

    Optional<TokenPair> login(String username, String password) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(username, password));
        } catch (AuthenticationException e) {
            log.info("Login failed: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
        // Scopes come from the user record, not authentication.getAuthorities(): Spring Security 7 adds
        // factor authorities such as FACTOR_PASSWORD there, which describe this login, not permissions.
        UserDetails user = (UserDetails) authentication.getPrincipal();
        return Optional.of(new TokenPair(
                accessTokens.issue(user.getUsername(), scopes(user.getAuthorities())),
                refreshTokens.startFamily(user.getUsername())));
    }

    Optional<TokenPair> refresh(String presentedRefreshToken) {
        RefreshResult result = refreshTokens.rotate(presentedRefreshToken);
        if (result instanceof RefreshResult.Rejected rejected) {
            log.info("Refresh rejected: {}", rejected.reason());
            return Optional.empty();
        }
        RefreshResult.Rotated rotated = (RefreshResult.Rotated) result;

        // Re-check the account on every refresh: a disabled user is locked out within one access-token
        // lifetime, and scope changes take effect at the next refresh.
        Optional<UserDetails> user = activeUser(rotated.subject());
        if (user.isEmpty()) {
            refreshTokens.revokeFamily(rotated.next().familyId(), RevocationReason.ACCOUNT_DISABLED);
            return Optional.empty();
        }
        return Optional.of(new TokenPair(
                accessTokens.issue(rotated.subject(), scopes(user.get().getAuthorities())),
                rotated.next()));
    }

    void logout(String presentedRefreshToken) {
        refreshTokens.revokeFamilyOf(presentedRefreshToken);
    }

    private Optional<UserDetails> activeUser(String username) {
        try {
            UserDetails user = users.loadUserByUsername(username);
            boolean active = user.isEnabled() && user.isAccountNonLocked() && user.isAccountNonExpired();
            return active ? Optional.of(user) : Optional.empty();
        } catch (UsernameNotFoundException e) {
            return Optional.empty();
        }
    }

    private static List<String> scopes(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }
}
