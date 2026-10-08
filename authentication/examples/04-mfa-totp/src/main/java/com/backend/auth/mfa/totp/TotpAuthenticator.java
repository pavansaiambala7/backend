package com.backend.auth.mfa.totp;

import java.time.Clock;
import java.util.OptionalLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.backend.auth.mfa.crypto.SecretEncryptor;
import com.backend.auth.mfa.otp.Totp;

/** Verifies login codes against a user's active authenticator, accepting each time step at most once. */
@Component
public class TotpAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(TotpAuthenticator.class);

    private final TotpCredentialRepository credentials;
    private final SecretEncryptor encryptor;
    private final Totp totp;
    private final TotpProperties properties;
    private final Clock clock;

    public TotpAuthenticator(TotpCredentialRepository credentials, SecretEncryptor encryptor, Totp totp,
                             TotpProperties properties, Clock clock) {
        this.credentials = credentials;
        this.encryptor = encryptor;
        this.totp = totp;
        this.properties = properties;
        this.clock = clock;
    }

    /** True if {@code code} is valid now and its time step was not used before. Throttling is the caller's job. */
    public boolean verify(String username, String code) {
        TotpCredential credential = credentials.findByUsername(username).filter(TotpCredential::active).orElse(null);
        if (credential == null) {
            return false;
        }
        byte[] secret = encryptor.decrypt(credential.encryptedSecret(), TotpCredential.associatedData(username));
        OptionalLong step = totp.matchingStep(secret, normalize(code), clock.instant(), properties.allowedDriftSteps());
        if (step.isEmpty()) {
            return false;
        }
        if (!credentials.recordUse(username, step.getAsLong())) {
            // RFC 6238 5.2 / NIST SP 800-63B-4 3.1.4.2: a code is accepted only once. A reuse may mean someone
            // watched or relayed the code; a real system would alert the user.
            log.warn("Rejected a reused TOTP code for user {} (time step {})", username, step.getAsLong());
            return false;
        }
        return true;
    }

    /** People type "123 456" or paste with a trailing space. */
    static String normalize(String code) {
        return code == null ? "" : code.replaceAll("\\s", "");
    }
}
