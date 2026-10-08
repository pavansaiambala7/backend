package com.backend.auth.resourceserver.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * What this API trusts, bound from {@code resourceserver.*} in application.yml.
 *
 * @param issuer    the only accepted {@code iss}, character for character
 * @param jwkSetUri where the issuer publishes its public signing keys
 * @param audience  the value that must appear in {@code aud}: the identifier of this API
 */
@ConfigurationProperties("resourceserver")
public record ResourceServerProperties(String issuer, String jwkSetUri, String audience) {
}
