package com.backend.auth.authserver.token;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import com.backend.auth.authserver.AuthServerProperties;
import com.backend.auth.authserver.user.UserProfiles;

@Configuration(proxyBeanMethods = false)
class TokenConfig {

    /** Spring Authorization Server applies this bean to every JWT it issues. */
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenClaimsCustomizer(AuthServerProperties properties, UserProfiles userProfiles) {
        return new TokenClaimsCustomizer(properties.apis(), userProfiles);
    }
}
