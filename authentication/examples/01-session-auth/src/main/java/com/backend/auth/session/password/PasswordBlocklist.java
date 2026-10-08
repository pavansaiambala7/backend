package com.backend.auth.session.password;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import org.jspecify.annotations.Nullable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Passwords that attackers try first: a bundled list of common/breached values plus, optionally,
 * the Have I Been Pwned corpus. NIST SP 800-63B-4 requires this check whenever a password is set.
 *
 * <p>Deliberately not exposed as a {@link CompromisedPasswordChecker} bean: Spring Security would
 * then also check at login and reject correct-but-breached passwords, which needs a password reset
 * flow this example does not have.
 */
@Component
class PasswordBlocklist {

    private static final String BUNDLED_LIST = "password-blocklist.txt";

    private final Set<String> bundled;
    private final @Nullable CompromisedPasswordChecker haveIBeenPwned;

    PasswordBlocklist(PasswordProperties properties) {
        this.bundled = loadBundledList();
        this.haveIBeenPwned = properties.hibpCheckEnabled() ? haveIBeenPwnedChecker() : null;
    }

    /** @param password an NFC-normalized password */
    boolean contains(String password) {
        if (bundled.contains(password.toLowerCase(Locale.ROOT))) {
            return true;
        }
        // Spring's checker fails open: if the API is unreachable it logs and returns "not
        // compromised", so an HIBP outage cannot block registrations.
        return haveIBeenPwned != null && haveIBeenPwned.check(password).isCompromised();
    }

    private static CompromisedPasswordChecker haveIBeenPwnedChecker() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(1));
        requestFactory.setReadTimeout(Duration.ofSeconds(2));
        HaveIBeenPwnedRestApiPasswordChecker checker = new HaveIBeenPwnedRestApiPasswordChecker();
        checker.setRestClient(RestClient.builder()
                .baseUrl("https://api.pwnedpasswords.com/range/")
                .requestFactory(requestFactory)
                // Padding makes every response a similar size, so an observer of the TLS traffic
                // cannot infer which hash prefix was requested from the response length.
                .defaultHeader("Add-Padding", "true")
                .defaultHeader("User-Agent", "backend-auth-session-example")
                .build());
        return checker;
    }

    private static Set<String> loadBundledList() {
        ClassPathResource resource = new ClassPathResource(BUNDLED_LIST);
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
            return reader.lines()
                    .map(String::strip)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .map(line -> line.toLowerCase(Locale.ROOT))
                    .collect(Collectors.toUnmodifiableSet());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + BUNDLED_LIST, e);
        }
    }
}
