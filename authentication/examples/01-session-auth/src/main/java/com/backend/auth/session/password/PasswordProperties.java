package com.backend.auth.session.password;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param hibpCheckEnabled also query the Have I Been Pwned range API (k-anonymity: only the
 *                         first 5 hex characters of the SHA-1 leave the server). Off by default so
 *                         the demo and tests work offline; on in the "prod" profile.
 */
@ConfigurationProperties("auth.password")
record PasswordProperties(boolean hibpCheckEnabled) {
}
