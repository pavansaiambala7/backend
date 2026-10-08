package com.backend.auth.mfa.recovery;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.backend.auth.mfa.otp.Base32;
import com.backend.auth.mfa.recovery.RecoveryCodeRepository.StoredRecoveryCode;

/**
 * Single-use recovery codes: the fallback when the authenticator app is lost.
 *
 * <p>Each code is 80 random bits, written as 16 Base32 characters in groups of four ({@code ABCD-EFGH-IJKL-MNOP}).
 * NIST SP 800-63B-4 asks for at least 64 bits (4.2.1.1) and, because 80 bits is below 112, a <em>salted password
 * hash</em> for storage (3.1.2.2). So codes are stored with the application's {@link PasswordEncoder} (Argon2id):
 * a stolen table does not reveal them, and testing guesses offline is as slow as for passwords.
 */
@Service
public class RecoveryCodeService {

    public static final int CODES_PER_SET = 10;

    private static final Logger log = LoggerFactory.getLogger(RecoveryCodeService.class);
    private static final int CODE_BYTES = 10;            // 80 bits -> exactly 16 Base32 characters
    private static final int NORMALIZED_LENGTH = 16;

    private final SecureRandom random = new SecureRandom();
    private final RecoveryCodeRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    public RecoveryCodeService(RecoveryCodeRepository repository, PasswordEncoder passwordEncoder, Clock clock) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
    }

    /**
     * Creates a new set and invalidates every earlier code.
     *
     * @return the codes in plain text; this is the only time they exist outside the user's hands
     */
    @Transactional
    public List<String> issueNewSet(String username) {
        List<String> codes = new ArrayList<>(CODES_PER_SET);
        List<String> hashes = new ArrayList<>(CODES_PER_SET);
        for (int i = 0; i < CODES_PER_SET; i++) {
            byte[] bytes = new byte[CODE_BYTES];
            random.nextBytes(bytes);
            String normalized = Base32.encodeUnpadded(bytes);
            codes.add(format(normalized));
            hashes.add(passwordEncoder.encode(normalized));
        }
        repository.replaceAll(username, hashes, clock.instant());
        log.info("Issued {} new recovery codes for user {}", CODES_PER_SET, username);
        return codes;
    }

    /**
     * Consumes a code if it matches one of the user's unused codes. Throttling is the caller's job.
     *
     * @return true exactly once per code
     */
    @Transactional
    public boolean redeem(String username, String submitted) {
        String normalized = normalize(submitted);
        if (normalized.length() != NORMALIZED_LENGTH) {
            return false;   // also keeps arbitrarily long input away from the password hash
        }
        // Salted hashes cannot be looked up by value, so compare against each unused code (at most ten).
        for (StoredRecoveryCode stored : repository.findUnused(username)) {
            if (passwordEncoder.matches(normalized, stored.codeHash())) {
                boolean consumed = repository.markUsed(stored.id(), clock.instant());
                if (consumed) {
                    log.warn("Recovery code used by user {}; {} left", username, repository.countUnused(username));
                }
                return consumed;
            }
        }
        return false;
    }

    public int remaining(String username) {
        return repository.countUnused(username);
    }

    /** Accepts any case, with or without dashes and spaces. */
    static String normalize(String code) {
        return code == null ? "" : code.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
    }

    private static String format(String normalized) {
        return String.join("-", normalized.substring(0, 4), normalized.substring(4, 8),
                normalized.substring(8, 12), normalized.substring(12, 16));
    }
}
