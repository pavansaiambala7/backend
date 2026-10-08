package com.backend.auth.apikeys.admin;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.backend.auth.apikeys.apikey.ApiKeyExceptions.InvalidKeyRequest;
import com.backend.auth.apikeys.apikey.ApiKeyExceptions.KeyNotFound;
import com.backend.auth.apikeys.apikey.ApiKeyExceptions.KeyNotRotatable;
import com.backend.auth.apikeys.apikey.ApiKeyService;
import com.backend.auth.apikeys.apikey.IssuedApiKey;

import jakarta.validation.Valid;

/** Key management for administrators. Every call is limited to the administrator's own account. */
@RestController
@RequestMapping("/admin/api-keys")
class ApiKeyAdminController {

    private final ApiKeyService keys;
    private final Clock clock;

    ApiKeyAdminController(ApiKeyService keys, Clock clock) {
        this.keys = keys;
        this.clock = clock;
    }

    @PostMapping
    ResponseEntity<CreatedApiKey> create(@AuthenticationPrincipal AdminUser admin,
            @Valid @RequestBody CreateApiKeyRequest request) {
        Duration lifetime = request.expiresInDays() == null ? null : Duration.ofDays(request.expiresInDays());
        IssuedApiKey issued = keys.create(admin.owner(), request.name(), request.scopes(), lifetime);
        return ResponseEntity.created(location(issued)).body(CreatedApiKey.of(issued));
    }

    @GetMapping
    List<ApiKeyView> list(@AuthenticationPrincipal AdminUser admin) {
        return keys.list(admin.owner()).stream().map(key -> ApiKeyView.of(key, clock.instant())).toList();
    }

    @GetMapping("/{id}")
    ApiKeyView get(@AuthenticationPrincipal AdminUser admin, @PathVariable UUID id) {
        return ApiKeyView.of(keys.get(admin.owner(), id), clock.instant());
    }

    @PostMapping("/{id}/revoke")
    ApiKeyView revoke(@AuthenticationPrincipal AdminUser admin, @PathVariable UUID id) {
        return ApiKeyView.of(keys.revoke(admin.owner(), id), clock.instant());
    }

    @PostMapping("/{id}/rotate")
    ResponseEntity<RotatedApiKey> rotate(@AuthenticationPrincipal AdminUser admin, @PathVariable UUID id) {
        var rotation = keys.rotate(admin.owner(), id);
        var body = new RotatedApiKey(CreatedApiKey.of(rotation.replacement()), ApiKeyView.of(rotation.previous(), clock.instant()));
        return ResponseEntity.created(location(rotation.replacement())).body(body);
    }

    @ExceptionHandler
    ProblemDetail notFound(KeyNotFound exception) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, "No such API key.");
    }

    @ExceptionHandler
    ProblemDetail invalid(InvalidKeyRequest exception) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler
    ProblemDetail notRotatable(KeyNotRotatable exception) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, exception.getMessage());
    }

    private static URI location(IssuedApiKey issued) {
        return URI.create("/admin/api-keys/" + issued.key().id());
    }
}
