package com.backend.auth.mfa.security;

import java.io.Serial;
import java.util.Collection;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * The result of a successful second-factor check.
 *
 * <p>It implements {@link #toBuilder()} because Spring Security's MFA support needs it: when the authentication
 * filter runs in MFA mode and the session already holds an {@code Authentication} for the same user, it uses the
 * builder to copy the earlier factor authorities (here {@code FACTOR_PASSWORD}) into this one. Without the builder
 * the password factor would be dropped and the user could never satisfy "password AND code".
 */
public final class SecondFactorAuthentication extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 1L;

    private final UserDetails principal;

    public SecondFactorAuthentication(UserDetails principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        setAuthenticated(true);
    }

    private SecondFactorAuthentication(Builder<?> builder) {
        super(builder);
        this.principal = builder.principal;
    }

    @Override
    public UserDetails getPrincipal() {
        return principal;
    }

    /** Nothing to keep: the code was single-use. */
    @Override
    public @Nullable Object getCredentials() {
        return null;
    }

    @Override
    public Builder<?> toBuilder() {
        return new Builder<>(this);
    }

    public static final class Builder<B extends Builder<B>> extends AbstractAuthenticationBuilder<B> {

        private UserDetails principal;

        private Builder(SecondFactorAuthentication authentication) {
            super(authentication);
            this.principal = authentication.principal;
        }

        @Override
        @SuppressWarnings("unchecked")
        public B principal(@Nullable Object principal) {
            Assert.isInstanceOf(UserDetails.class, principal, "principal must be a UserDetails");
            this.principal = (UserDetails) principal;
            return (B) this;
        }

        @Override
        public SecondFactorAuthentication build() {
            return new SecondFactorAuthentication(this);
        }
    }
}
