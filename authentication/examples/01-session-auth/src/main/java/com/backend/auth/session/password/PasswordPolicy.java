package com.backend.auth.session.password;

import java.text.Normalizer;
import java.util.Locale;
import java.util.Set;

import org.springframework.stereotype.Component;

/**
 * NIST SP 800-63B-4 password rules for an account where the password is the only factor:
 * at least 15 characters, long passwords allowed, no composition rules, no forced rotation,
 * and a blocklist check. Rejections always say why, as NIST requires.
 */
@Component
public class PasswordPolicy {

    /** NIST: SHALL be at least 15 when the password is the only factor (8 if MFA is mandatory). */
    public static final int MIN_LENGTH = 15;
    /** NIST: SHOULD permit at least 64. The cap only bounds hashing cost for absurd inputs. */
    public static final int MAX_LENGTH = 128;

    private static final int MIN_EMAIL_LOCAL_PART_TO_CHECK = 4;
    private static final Set<String> SERVICE_WORDS = Set.of("sessionauth", "session-auth", "session auth");

    private final PasswordBlocklist blocklist;

    PasswordPolicy(PasswordBlocklist blocklist) {
        this.blocklist = blocklist;
    }

    /**
     * @param normalizedEmail the account's email, already normalized
     * @throws WeakPasswordException with a user-facing reason
     */
    public void validate(String rawPassword, String normalizedEmail) {
        String password = Normalizer.normalize(rawPassword, Normalizer.Form.NFC);
        // Count Unicode code points, not UTF-16 units: an emoji is one character to the user.
        int length = password.codePointCount(0, password.length());
        if (length < MIN_LENGTH) {
            throw new WeakPasswordException("Use at least " + MIN_LENGTH
                    + " characters. A few unrelated words make a strong, memorable passphrase.");
        }
        if (length > MAX_LENGTH) {
            throw new WeakPasswordException("Use at most " + MAX_LENGTH + " characters.");
        }
        String lower = password.toLowerCase(Locale.ROOT);
        if (containsContextWords(lower, normalizedEmail)) {
            throw new WeakPasswordException("Don't use your email address or the name of this service in your password.");
        }
        if (blocklist.contains(password)) {
            throw new WeakPasswordException("This password appears in a list of breached or common passwords. Please choose a different one.");
        }
    }

    private static boolean containsContextWords(String lowerPassword, String normalizedEmail) {
        String localPart = normalizedEmail.split("@", 2)[0];
        boolean containsEmail = lowerPassword.contains(normalizedEmail)
                || (localPart.length() >= MIN_EMAIL_LOCAL_PART_TO_CHECK && lowerPassword.contains(localPart));
        return containsEmail || SERVICE_WORDS.stream().anyMatch(lowerPassword::contains);
    }
}
