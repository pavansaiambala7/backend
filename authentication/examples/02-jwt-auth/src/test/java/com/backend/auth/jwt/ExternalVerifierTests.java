package com.backend.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.jayway.jsonpath.JsonPath;

/**
 * Another service, with nothing but the issuer's URL, verifies our tokens through the JWKS endpoint.
 * Runs a real Tomcat on a random port, so it also shows the Set-Cookie header exactly as sent on the wire.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ExternalVerifierTests {

    @LocalServerPort
    int port;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void aSeparateResourceServerCanVerifyTokensUsingOnlyTheJwksUrl() throws Exception {
        HttpResponse<String> login = login();
        assertThat(login.statusCode()).isEqualTo(200);
        String accessToken = JsonPath.read(login.body(), "$.access_token");

        NimbusJwtDecoder otherService = NimbusJwtDecoder
                .withJwkSetUri("http://localhost:" + port + "/.well-known/jwks.json")
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        otherService.setJwtValidator(JwtValidators.createAtJwtValidator()
                .issuer(TestTokens.ISSUER)
                .audience(TestTokens.AUDIENCE)
                .build());

        Jwt jwt = otherService.decode(accessToken);
        assertThat(jwt.getSubject()).isEqualTo("alice");
        assertThat(jwt.getClaimAsString("scope")).isEqualTo("orders:read orders:write");

        // The same verifier refuses a token for a different audience (another API of the same issuer).
        NimbusJwtDecoder billingService = NimbusJwtDecoder
                .withJwkSetUri("http://localhost:" + port + "/.well-known/jwks.json")
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        billingService.setJwtValidator(JwtValidators.createAtJwtValidator()
                .issuer(TestTokens.ISSUER)
                .audience("billing-api")
                .build());
        assertThatThrownBy(() -> billingService.decode(accessToken)).isInstanceOf(JwtException.class);
    }

    @Test
    void refreshCookieOnTheWireIsHttpOnlySecureSameSiteStrictAndPathScoped() throws Exception {
        List<String> setCookies = login().headers().allValues("Set-Cookie");

        assertThat(setCookies).singleElement().asString()
                .startsWith(AuthFlows.COOKIE + "=")
                .contains("; Path=/auth", "; Secure", "; HttpOnly", "; SameSite=Strict", "; Max-Age=86400")
                .doesNotContain("Domain");
    }

    private HttpResponse<String> login() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/auth/login"))
                .header("Content-Type", "application/json")
                .header(AuthFlows.CSRF_HEADER, "1")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"username\":\"alice\",\"password\":\"" + AuthFlows.ALICE_PASSWORD + "\"}"))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
