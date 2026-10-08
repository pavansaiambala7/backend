package com.backend.auth.session;

import static com.backend.auth.session.TestSupport.PASSWORD;
import static com.backend.auth.session.TestSupport.createAccount;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import com.backend.auth.session.account.UserAccountRepository;

/**
 * Runs the "prod" profile in a real Tomcat on a random port and checks the actual Set-Cookie
 * headers, which MockMvc cannot show (they are written by the servlet container).
 *
 * <p>Every request carries {@code X-Forwarded-Proto: https}, exactly like a TLS-terminating load
 * balancer would; with {@code server.forward-headers-strategy=native}, Tomcat trusts it because the
 * request comes from 127.0.0.1, an internal-proxy address.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "auth.password.hibp-check-enabled=false")   // no network calls in tests
@ActiveProfiles("prod")
class ProductionCookieTests {

    private static final String COOKIE_NAME = "__Host-SESSION";
    private static final Pattern CSRF_FIELD = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"");

    @LocalServerPort
    int port;

    @Autowired
    UserAccountRepository accounts;

    @Autowired
    PasswordEncoder passwordEncoder;

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    @Test
    void sessionCookieIsHostPrefixedSecureHttpOnlyAndSameSiteLax() throws Exception {
        HttpResponse<String> loginPage = get("/login", null);

        String setCookie = sessionSetCookie(loginPage);
        assertThat(setCookie)
                .startsWith(COOKIE_NAME + "=")
                .contains("Path=/", "Secure", "HttpOnly", "SameSite=Lax")
                .doesNotContainIgnoringCase("Domain=")      // required by __Host-, and host-only anyway
                .doesNotContainIgnoringCase("Max-Age");     // a browser-session cookie; expiry is server-side
        assertThat(loginPage.headers().firstValue("Strict-Transport-Security"))
                .hasValueSatisfying(hsts -> assertThat(hsts).contains("max-age=31536000", "includeSubDomains"));
    }

    @Test
    void loginIssuesANewSessionIdAndThePreLoginIdBecomesWorthless() throws Exception {
        String email = createAccount(accounts, passwordEncoder, "prod");
        HttpResponse<String> loginPage = get("/login", null);
        String preLoginId = cookieValue(sessionSetCookie(loginPage));

        HttpResponse<String> login = post("/login", preLoginId, Map.of(
                "username", email, "password", PASSWORD, "_csrf", csrfToken(loginPage)));

        assertThat(login.statusCode()).isEqualTo(302);
        assertThat(login.headers().firstValue("Location")).hasValueSatisfying(location -> assertThat(location).endsWith("/"));
        String postLoginId = cookieValue(sessionSetCookie(login));
        assertThat(postLoginId).isNotEqualTo(preLoginId);

        HttpResponse<String> withNewId = get("/", postLoginId);
        assertThat(withNewId.statusCode()).isEqualTo(200);
        assertThat(withNewId.body()).contains(email);

        HttpResponse<String> withPlantedId = get("/", preLoginId);
        assertThat(withPlantedId.statusCode()).isEqualTo(302);
        assertThat(withPlantedId.headers().firstValue("Location")).hasValueSatisfying(l -> assertThat(l).contains("/login"));
    }

    @Test
    void logoutExpiresTheCookieWithMatchingAttributesAndClearsSiteData() throws Exception {
        String email = createAccount(accounts, passwordEncoder, "prodlogout");
        HttpResponse<String> loginPage = get("/login", null);
        HttpResponse<String> login = post("/login", cookieValue(sessionSetCookie(loginPage)), Map.of(
                "username", email, "password", PASSWORD, "_csrf", csrfToken(loginPage)));
        String sessionId = cookieValue(sessionSetCookie(login));
        HttpResponse<String> home = get("/", sessionId);

        HttpResponse<String> logout = post("/logout", sessionId, Map.of("_csrf", csrfToken(home)));

        assertThat(logout.statusCode()).isEqualTo(302);
        // A __Host- cookie can only be deleted by a Set-Cookie that also has Secure and Path=/.
        // Tomcat expresses "delete" (Max-Age=0) as an Expires date in the past.
        assertThat(sessionSetCookie(logout))
                .startsWith(COOKIE_NAME + "=;")
                .contains("Expires=Thu, 01 Jan 1970", "Path=/", "Secure");
        assertThat(logout.headers().firstValue("Clear-Site-Data")).hasValue("\"cookies\"");
        assertThat(get("/", sessionId).statusCode()).isEqualTo(302);
    }

    private HttpResponse<String> get(String path, String sessionId) throws IOException, InterruptedException {
        return http.send(request(path, sessionId).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String sessionId, Map<String, String> form)
            throws IOException, InterruptedException {
        String body = form.entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest request = request(path, sessionId)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpRequest.Builder request(String path, String sessionId) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("X-Forwarded-Proto", "https");
        if (sessionId != null) {
            builder.header("Cookie", COOKIE_NAME + "=" + sessionId);
        }
        return builder;
    }

    private static String sessionSetCookie(HttpResponse<?> response) {
        return response.headers().allValues("Set-Cookie").stream()
                .filter(header -> header.startsWith(COOKIE_NAME + "="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No " + COOKIE_NAME + " cookie in " + response.headers().map()));
    }

    private static String cookieValue(String setCookie) {
        return setCookie.substring(COOKIE_NAME.length() + 1, setCookie.indexOf(';'));
    }

    private static String csrfToken(HttpResponse<String> page) {
        Matcher matcher = CSRF_FIELD.matcher(page.body());
        assertThat(matcher.find()).as("page contains a CSRF field").isTrue();
        return matcher.group(1);
    }
}
