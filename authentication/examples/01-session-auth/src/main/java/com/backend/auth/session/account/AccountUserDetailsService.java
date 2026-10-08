package com.backend.auth.session.account;

import org.jspecify.annotations.Nullable;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Bridges the user table to Spring Security. Because this bean implements both interfaces, Spring
 * Security's auto-configured {@code DaoAuthenticationProvider} also uses it to re-hash passwords
 * whose stored format is outdated (for example {@code {bcrypt}} or weaker Argon2 parameters).
 */
@Service
class AccountUserDetailsService implements UserDetailsService, UserDetailsPasswordService {

    private final UserAccountRepository accounts;

    AccountUserDetailsService(UserAccountRepository accounts) {
        this.accounts = accounts;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        UserAccount account = accounts.findByEmail(UserAccount.normalizeEmail(username))
                // DaoAuthenticationProvider turns this into the same BadCredentialsException as a wrong
                // password and still runs a dummy hash, so neither the message nor the response time
                // tells an attacker whether the account exists.
                .orElseThrow(() -> new UsernameNotFoundException("Unknown user"));
        return User.withUsername(account.getEmail())
                .password(account.getPasswordHash())
                .roles("USER")
                .build();
    }

    /** Called after a successful login when {@code PasswordEncoder.upgradeEncoding(storedHash)} is true. */
    @Override
    @Transactional
    public UserDetails updatePassword(UserDetails user, @Nullable String newEncodedPassword) {
        if (newEncodedPassword == null) {
            return user;
        }
        accounts.findByEmail(UserAccount.normalizeEmail(user.getUsername()))
                .ifPresent(account -> account.changePasswordHash(newEncodedPassword));
        return User.withUserDetails(user).password(newEncodedPassword).build();
    }
}
