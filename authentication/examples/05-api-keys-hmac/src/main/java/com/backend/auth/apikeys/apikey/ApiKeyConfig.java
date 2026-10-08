package com.backend.auth.apikeys.apikey;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
class ApiKeyConfig {

    /** {@code new SecureRandom()} is the non-blocking OS CSPRNG; {@code getInstanceStrong()} can block on Linux. */
    @Bean
    ApiKeyFormat apiKeyFormat(ApiKeyProperties properties) {
        return new ApiKeyFormat(properties.environment(), new SecureRandom());
    }

    @Bean
    ApiKeyHasher apiKeyHasher(ApiKeyProperties properties) {
        return new ApiKeyHasher(Base64.getDecoder().decode(properties.pepper()));
    }
}
