package com.backend.auth.session.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Length and blocklist rules for the password live in PasswordPolicy, which explains rejections. */
record RegistrationForm(
        @NotBlank(message = "Enter your email address.")
        @Email(message = "Enter a valid email address.")
        @Size(max = 320, message = "Email addresses are at most 320 characters.")
        String email,

        @NotBlank(message = "Choose a password.")
        String password) {

    static RegistrationForm empty() {
        return new RegistrationForm("", "");
    }
}
