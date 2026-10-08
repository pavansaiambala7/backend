package com.backend.auth.jwt.web;

import java.time.Duration;
import java.util.Optional;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.backend.auth.jwt.refresh.IssuedRefreshToken;
import com.backend.auth.jwt.refresh.RefreshTokenProperties;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

/** Writes, reads and clears the refresh-token cookie. */
@Component
class RefreshCookies {

    private final RefreshTokenProperties properties;

    RefreshCookies(RefreshTokenProperties properties) {
        this.properties = properties;
    }

    /** The cookie lives exactly as long as the token it carries. */
    ResponseCookie create(IssuedRefreshToken token) {
        return base(token.value()).maxAge(token.lifetime()).build();
    }

    /** Same name, path and attributes as the original, otherwise the browser keeps the old cookie. */
    ResponseCookie clear() {
        return base("").maxAge(Duration.ZERO).build();
    }

    Optional<String> read(HttpServletRequest request) {
        return Optional.ofNullable(WebUtils.getCookie(request, properties.cookieName())).map(Cookie::getValue);
    }

    private ResponseCookie.ResponseCookieBuilder base(String value) {
        return ResponseCookie.from(properties.cookieName(), value)
                .httpOnly(true)                  // JavaScript (and therefore XSS) cannot read the token
                .secure(true)                    // never sent over plain HTTP
                .sameSite("Strict")              // never sent on requests started by another site
                .path(properties.cookiePath());  // only /auth/**; no Domain attribute: host-only
    }
}
