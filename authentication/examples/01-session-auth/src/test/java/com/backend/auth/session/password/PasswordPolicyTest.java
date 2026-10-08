package com.backend.auth.session.password;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PasswordPolicyTest {

    private static final String EMAIL = "alice.smith@example.com";

    private final PasswordPolicy policy = new PasswordPolicy(new PasswordBlocklist(new PasswordProperties(false)));

    @Test
    void acceptsALongPassphraseWithoutAnyCompositionRules() {
        assertThatCode(() -> policy.validate("plaid otter sings at dawn", EMAIL)).doesNotThrowAnyException();
    }

    @Test
    void rejectsShortPasswordsHoweverComplex() {
        assertThatThrownBy(() -> policy.validate("Xy7$kq!2Lm#9", EMAIL))
                .isInstanceOf(WeakPasswordException.class)
                .hasMessageContaining("at least 15 characters");
    }

    @Test
    void countsUnicodeCodePointsNotUtf16Units() {
        String fifteenEmoji = "🔐".repeat(15);   // 15 code points, 30 UTF-16 units
        String eightEmoji = "🔐".repeat(8);      // 8 code points, 16 UTF-16 units

        assertThatCode(() -> policy.validate(fifteenEmoji, EMAIL)).doesNotThrowAnyException();
        assertThatThrownBy(() -> policy.validate(eightEmoji, EMAIL)).isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void acceptsAtLeast64CharactersButBoundsAbsurdLengths() {
        assertThatCode(() -> policy.validate("a sentence that is long ".repeat(5), EMAIL)).doesNotThrowAnyException();
        assertThatThrownBy(() -> policy.validate("x".repeat(PasswordPolicy.MAX_LENGTH + 1), EMAIL))
                .hasMessageContaining("at most");
    }

    @Test
    void rejectsPasswordsBuiltFromTheEmailAddress() {
        assertThatThrownBy(() -> policy.validate("alice.smith-2026-forever", EMAIL))
                .hasMessageContaining("email address");
    }

    @Test
    void rejectsBlocklistedPasswordsCaseInsensitively() {
        assertThatThrownBy(() -> policy.validate("PasswordPassword", EMAIL))
                .hasMessageContaining("breached or common passwords");
    }
}
