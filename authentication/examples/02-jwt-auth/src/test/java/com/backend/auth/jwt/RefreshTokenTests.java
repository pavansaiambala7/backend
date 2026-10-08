package com.backend.auth.jwt;

import static com.backend.auth.jwt.AuthFlows.COOKIE;
import static com.backend.auth.jwt.AuthFlows.CSRF_HEADER;
import static com.backend.auth.jwt.AuthFlows.bearer;
import static com.backend.auth.jwt.AuthFlows.logoutRequest;
import static com.backend.auth.jwt.AuthFlows.refreshRequest;
import static com.backend.auth.jwt.AuthFlows.sha256Hex;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.backend.auth.jwt.AuthFlows.Tokens;
import com.backend.auth.jwt.refresh.IssuedRefreshToken;
import com.backend.auth.jwt.refresh.RefreshResult;
import com.backend.auth.jwt.refresh.RefreshToken;
import com.backend.auth.jwt.refresh.RefreshTokenRepository;
import com.backend.auth.jwt.refresh.RefreshTokenService;
import com.backend.auth.jwt.refresh.RevocationReason;

@SpringBootTest
@AutoConfigureMockMvc
class RefreshTokenTests {

    /** Test-only password for users created by a test. */
    private static final String TEMP_PASSWORD = "temporary-test-passphrase";

    @Autowired
    MockMvc mvc;

    @Autowired
    RefreshTokenRepository repository;

    @Autowired
    RefreshTokenService refreshTokens;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    InMemoryUserDetailsManager users;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void refreshRotatesTheRefreshTokenAndIssuesANewAccessToken() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);

        MvcResult result = mvc.perform(refreshRequest(login.refreshToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.scope").value("orders:read orders:write"))
                .andReturn();
        Tokens refreshed = AuthFlows.tokens(result);

        assertThat(refreshed.refreshToken()).isNotNull().isNotEqualTo(login.refreshToken());
        assertThat(refreshed.accessToken()).isNotEqualTo(login.accessToken());
        mvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, bearer(refreshed.accessToken())))
                .andExpect(status().isOk());

        RefreshToken old = stored(login.refreshToken());
        RefreshToken next = stored(refreshed.refreshToken());
        assertThat(old.getUsedAt()).isNotNull();
        assertThat(next.getUsedAt()).isNull();
        assertThat(next.getFamilyId()).isEqualTo(old.getFamilyId());
        assertThat(next.getParentId()).isEqualTo(old.getId());
        assertThat(next.getExpiresAt()).isEqualTo(old.getExpiresAt());   // rotation never extends the login
    }

    @Test
    void reusingARotatedRefreshTokenRevokesTheWholeFamily() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);
        String stolenCopy = login.refreshToken();
        String legitimateNext = AuthFlows.tokens(
                mvc.perform(refreshRequest(login.refreshToken())).andExpect(status().isOk()).andReturn())
                .refreshToken();

        // The attacker replays the old token: rejected, and the cookie is cleared.
        mvc.perform(refreshRequest(stolenCopy))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_refresh_token"))
                .andExpect(result -> assertThat(result.getResponse().getHeader(HttpHeaders.SET_COOKIE))
                        .startsWith(COOKIE + "=;").contains("Max-Age=0"));

        // The legitimate client's current token died with the family: everyone must log in again.
        mvc.perform(refreshRequest(legitimateNext)).andExpect(status().isUnauthorized());

        List<RefreshToken> family = repository.findByFamilyIdOrderByIssuedAt(stored(stolenCopy).getFamilyId());
        assertThat(family).hasSize(2).allSatisfy(token -> {
            assertThat(token.getRevokedAt()).isNotNull();
            assertThat(token.getRevokeReason()).isEqualTo(RevocationReason.REUSE_DETECTED);
        });
    }

    @Test
    void reuseRevokesOnlyThatFamilyNotTheUsersOtherLogins() throws Exception {
        Tokens laptop = AuthFlows.loginAlice(mvc);
        Tokens phone = AuthFlows.loginAlice(mvc);
        mvc.perform(refreshRequest(laptop.refreshToken())).andExpect(status().isOk());
        mvc.perform(refreshRequest(laptop.refreshToken())).andExpect(status().isUnauthorized());   // reuse

        mvc.perform(refreshRequest(phone.refreshToken())).andExpect(status().isOk());
    }

    @Test
    void logoutRevokesTheFamilyAndClearsTheCookie() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);
        String rotated = AuthFlows.tokens(
                mvc.perform(refreshRequest(login.refreshToken())).andExpect(status().isOk()).andReturn())
                .refreshToken();

        mvc.perform(logoutRequest(rotated))
                .andExpect(status().isNoContent())
                .andExpect(result -> assertThat(result.getResponse().getHeader(HttpHeaders.SET_COOKIE))
                        .startsWith(COOKIE + "=;")
                        .contains("Max-Age=0", "Path=/auth", "HttpOnly", "Secure", "SameSite=Strict"));

        mvc.perform(refreshRequest(rotated)).andExpect(status().isUnauthorized());
        assertThat(repository.findByFamilyIdOrderByIssuedAt(stored(rotated).getFamilyId()))
                .allSatisfy(token -> assertThat(token.getRevokeReason()).isEqualTo(RevocationReason.LOGOUT));
    }

    @Test
    void accessTokenIssuedBeforeLogoutKeepsWorkingUntilItExpires() throws Exception {
        // The honest trade-off of self-contained tokens: logout kills the refresh token at once, but an
        // access token already handed out is valid until exp (at most 15 minutes). See the README for
        // the deny-list option when that is not acceptable.
        Tokens login = AuthFlows.loginAlice(mvc);
        mvc.perform(logoutRequest(login.refreshToken())).andExpect(status().isNoContent());

        mvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, bearer(login.accessToken())))
                .andExpect(status().isOk());
    }

    @Test
    void logoutWithoutAValidCookieStillSucceedsSoItRevealsNothing() throws Exception {
        mvc.perform(post("/auth/logout").header(CSRF_HEADER, "1")).andExpect(status().isNoContent());
        mvc.perform(logoutRequest("not-a-real-token")).andExpect(status().isNoContent());
    }

    @Test
    void refreshWithoutCookieOrWithUnknownTokenIsRejected() throws Exception {
        mvc.perform(post("/auth/refresh").header(CSRF_HEADER, "1")).andExpect(status().isUnauthorized());
        mvc.perform(refreshRequest("x".repeat(43))).andExpect(status().isUnauthorized());
        mvc.perform(refreshRequest("' or 1=1 --")).andExpect(status().isUnauthorized());
    }

    @Test
    void disabledAccountCannotRefreshAndItsFamilyIsRevoked() throws Exception {
        String username = createUser("orders:read");
        Tokens login = AuthFlows.login(mvc, username, TEMP_PASSWORD);

        users.updateUser(User.withUserDetails(users.loadUserByUsername(username)).disabled(true).build());

        mvc.perform(refreshRequest(login.refreshToken())).andExpect(status().isUnauthorized());
        assertThat(repository.findByFamilyIdOrderByIssuedAt(stored(login.refreshToken()).getFamilyId()))
                .allSatisfy(token -> assertThat(token.getRevokeReason()).isEqualTo(RevocationReason.ACCOUNT_DISABLED));
    }

    @Test
    void scopeChangesTakeEffectAtTheNextRefresh() throws Exception {
        String username = createUser("orders:read", "orders:write");
        Tokens login = AuthFlows.login(mvc, username, TEMP_PASSWORD);

        users.updateUser(User.withUserDetails(users.loadUserByUsername(username)).authorities("orders:read").build());

        mvc.perform(refreshRequest(login.refreshToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scope").value("orders:read"));
    }

    @Test
    void onlyTheSha256HashOfTheRefreshTokenIsStored() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);

        RefreshToken row = stored(login.refreshToken());
        assertThat(row.getTokenHash()).isEqualTo(sha256Hex(login.refreshToken())).hasSize(64);
        Integer rowsContainingRawToken = jdbc.sql("""
                        select count(*) from refresh_token
                        where token_hash = :raw or cast(id as varchar) = :raw or subject = :raw""")
                .param("raw", login.refreshToken())
                .query(Integer.class).single();
        assertThat(rowsContainingRawToken).isZero();
    }

    @Test
    void idleRefreshTokenExpires() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);
        backdate("issued_at", login.refreshToken(), Duration.ofDays(2));   // idle timeout is 1 day

        mvc.perform(refreshRequest(login.refreshToken())).andExpect(status().isUnauthorized());
    }

    @Test
    void familyEndsAtItsAbsoluteLifetimeHoweverActive() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);
        backdate("expires_at", login.refreshToken(), Duration.ofSeconds(1));

        mvc.perform(refreshRequest(login.refreshToken())).andExpect(status().isUnauthorized());
    }

    @Test
    void concurrentRefreshesWithTheSameTokenRotateOnceAndTheLoserIsTreatedAsReuse() throws Exception {
        IssuedRefreshToken token = refreshTokens.startFamily("alice");
        CountDownLatch start = new CountDownLatch(1);
        Callable<RefreshResult> refresh = () -> {
            start.await();
            return refreshTokens.rotate(token.value());
        };

        List<RefreshResult> results = new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            List<Future<RefreshResult>> futures = List.of(pool.submit(refresh), pool.submit(refresh));
            start.countDown();
            for (Future<RefreshResult> future : futures) {
                results.add(future.get());
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(results).filteredOn(RefreshResult.Rotated.class::isInstance).hasSize(1);
        assertThat(results).filteredOn(RefreshResult.Rejected.class::isInstance).singleElement()
                .isEqualTo(new RefreshResult.Rejected(RefreshResult.Reason.REUSE_DETECTED));
        // Two holders of one token: the server cannot tell which is legitimate, so the family is gone.
        assertThat(repository.findByFamilyIdOrderByIssuedAt(token.familyId()))
                .allSatisfy(row -> assertThat(row.getRevokedAt()).isNotNull());
    }

    private String createUser(String... scopes) {
        String username = "user-" + UUID.randomUUID();
        users.createUser(User.withUsername(username)
                .password(passwordEncoder.encode(TEMP_PASSWORD))
                .authorities(scopes)
                .build());
        return username;
    }

    private RefreshToken stored(String refreshToken) {
        return repository.findByTokenHash(sha256Hex(refreshToken)).orElseThrow();
    }

    private void backdate(String column, String refreshToken, Duration by) {
        jdbc.sql("update refresh_token set " + column + " = :value where token_hash = :hash")
                .param("value", Instant.now().minus(by))
                .param("hash", sha256Hex(refreshToken))
                .update();
    }
}
