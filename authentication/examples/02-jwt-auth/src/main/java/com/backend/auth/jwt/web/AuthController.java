package com.backend.auth.jwt.web;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

/**
 * {@code POST /auth/login}, {@code /auth/refresh} and {@code /auth/logout}. All three are guarded by
 * {@code AuthEndpointCsrfFilter} because they read or set the refresh-token cookie.
 */
@RestController
@RequestMapping(path = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
class AuthController {

    private final AuthService authService;
    private final RefreshCookies cookies;

    AuthController(AuthService authService, RefreshCookies cookies) {
        this.authService = authService;
        this.cookies = cookies;
    }

    /** JSON only: a cross-site HTML form cannot send application/json. */
    @PostMapping(path = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request.username(), request.password())
                .<ResponseEntity<?>>map(this::tokenResponse)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ErrorResponse.INVALID_CREDENTIALS));
    }

    @PostMapping("/refresh")
    ResponseEntity<?> refresh(HttpServletRequest request) {
        return cookies.read(request)
                .flatMap(authService::refresh)
                .<ResponseEntity<?>>map(this::tokenResponse)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .header(HttpHeaders.SET_COOKIE, cookies.clear().toString())
                        .body(ErrorResponse.INVALID_REFRESH_TOKEN));
    }

    /** Always 204, even without a valid cookie: logout must not reveal whether a token was valid. */
    @PostMapping("/logout")
    ResponseEntity<Void> logout(HttpServletRequest request) {
        cookies.read(request).ifPresent(authService::logout);
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cookies.clear().toString())
                .build();
    }

    private ResponseEntity<TokenResponse> tokenResponse(TokenPair tokens) {
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookies.create(tokens.refreshToken()).toString())
                .body(TokenResponse.from(tokens.accessToken()));
    }
}
