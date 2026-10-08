package com.backend.auth.session.account;

import java.time.Clock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.backend.auth.session.password.PasswordPolicy;
import com.backend.auth.session.password.WeakPasswordException;

@Service
public class RegistrationService {

    private static final Logger log = LoggerFactory.getLogger(RegistrationService.class);

    private final UserAccountRepository accounts;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final Clock clock;

    RegistrationService(UserAccountRepository accounts, PasswordEncoder passwordEncoder,
                        PasswordPolicy passwordPolicy, Clock clock) {
        this.accounts = accounts;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.clock = clock;
    }

    /**
     * Registers a new account. The caller sees the same outcome whether or not the address is
     * already registered, so this endpoint cannot be used to discover who has an account.
     *
     * @throws WeakPasswordException with a user-facing reason if the password violates the policy
     */
    public void register(String email, String rawPassword) {
        String normalizedEmail = UserAccount.normalizeEmail(email);
        passwordPolicy.validate(rawPassword, normalizedEmail);

        // Hash before the existence check: both branches then pay for one Argon2id computation,
        // so response time does not reveal which addresses are registered.
        String passwordHash = passwordEncoder.encode(rawPassword);

        if (accounts.existsByEmail(normalizedEmail)) {
            onDuplicateRegistration();
            return;
        }
        try {
            accounts.saveAndFlush(new UserAccount(normalizedEmail, passwordHash, clock.instant()));
        } catch (DataIntegrityViolationException concurrentDuplicate) {
            // Two registrations for the same address raced; the unique constraint picked a winner.
            onDuplicateRegistration();
        }
    }

    private void onDuplicateRegistration() {
        // A real application sends the existing owner an email ("someone tried to register with
        // your address; sign in or reset your password") instead of telling the requester.
        // The address itself is not logged: logs are not the place for personal data.
        log.info("Registration attempt for an address that already has an account");
    }
}
