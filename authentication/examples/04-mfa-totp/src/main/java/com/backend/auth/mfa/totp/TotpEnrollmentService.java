package com.backend.auth.mfa.totp;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend.auth.mfa.crypto.SecretEncryptor;
import com.backend.auth.mfa.otp.Base32;
import com.backend.auth.mfa.otp.OtpAuthUri;
import com.backend.auth.mfa.otp.Totp;
import com.backend.auth.mfa.recovery.RecoveryCodeService;
import com.backend.auth.mfa.security.SecondFactorThrottle;

/**
 * Adds a TOTP authenticator to an account in two steps: {@link #start} creates a secret, {@link #confirm} activates
 * it once the user proves their app produces valid codes. Until then the secret is pending and is not a factor;
 * activating on scan alone would lock out anyone whose scan silently failed.
 */
@Service
public class TotpEnrollmentService {

    /** 160 bits: RFC 4226's recommended key length, above NIST's 112-bit minimum. */
    private static final int SECRET_BYTES = 20;

    private static final Logger log = LoggerFactory.getLogger(TotpEnrollmentService.class);

    private final SecureRandom random = new SecureRandom();
    private final TotpCredentialRepository credentials;
    private final SecretEncryptor encryptor;
    private final RecoveryCodeService recoveryCodes;
    private final SecondFactorThrottle throttle;
    private final Totp totp;
    private final TotpProperties properties;
    private final Clock clock;

    public TotpEnrollmentService(TotpCredentialRepository credentials, SecretEncryptor encryptor,
                                 RecoveryCodeService recoveryCodes, SecondFactorThrottle throttle, Totp totp,
                                 TotpProperties properties, Clock clock) {
        this.credentials = credentials;
        this.encryptor = encryptor;
        this.recoveryCodes = recoveryCodes;
        this.throttle = throttle;
        this.totp = totp;
        this.properties = properties;
        this.clock = clock;
    }

    /** True once the user has a confirmed authenticator. */
    public boolean isEnrolled(String username) {
        return credentials.isActive(username);
    }

    /** Generates a new secret and stores it encrypted as pending, replacing any earlier pending one. */
    @Transactional
    public PendingEnrollment start(String username) {
        if (credentials.isActive(username)) {
            throw new IllegalStateException("User already has an active authenticator");
        }
        byte[] secret = new byte[SECRET_BYTES];
        random.nextBytes(secret);
        credentials.savePending(username, encryptor.encrypt(secret, TotpCredential.associatedData(username)), clock.instant());
        log.info("TOTP enrollment started for user {}", username);
        return toPendingEnrollment(username, secret);
    }

    /** The pending secret again, for redisplay after a wrong confirmation code. */
    @Transactional(readOnly = true)
    public Optional<PendingEnrollment> pending(String username) {
        return credentials.findByUsername(username)
                .filter(credential -> !credential.active())
                .map(credential -> toPendingEnrollment(username, decrypt(credential)));
    }

    /**
     * Activates the pending authenticator if {@code code} is valid for it, and issues recovery codes.
     *
     * @return the new recovery codes, or empty if the code was wrong or nothing was pending
     * @throws com.backend.auth.mfa.security.SecondFactorThrottledException after too many wrong codes
     */
    @Transactional
    public Optional<List<String>> confirm(String username, String code) {
        TotpCredential pending = credentials.findByUsername(username).filter(credential -> !credential.active()).orElse(null);
        if (pending == null) {
            return Optional.empty();
        }
        byte[] secret = decrypt(pending);
        boolean activated = throttle.attempt(username, () -> {
            OptionalLong step = totp.matchingStep(secret, TotpAuthenticator.normalize(code), clock.instant(),
                    properties.allowedDriftSteps());
            // Recording the confirming code's step means that same code cannot be replayed at the login step.
            return step.isPresent() && credentials.activate(username, step.getAsLong(), clock.instant());
        });
        if (!activated) {
            return Optional.empty();
        }
        log.info("TOTP authenticator activated for user {}", username);
        return Optional.of(recoveryCodes.issueNewSet(username));
    }

    private byte[] decrypt(TotpCredential credential) {
        return encryptor.decrypt(credential.encryptedSecret(), TotpCredential.associatedData(credential.username()));
    }

    private PendingEnrollment toPendingEnrollment(String username, byte[] secret) {
        String base32 = Base32.encodeUnpadded(secret);
        return new PendingEnrollment(base32, OtpAuthUri.totp(properties.issuer(), username, base32, totp));
    }
}
