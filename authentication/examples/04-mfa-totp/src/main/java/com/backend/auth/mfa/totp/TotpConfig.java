package com.backend.auth.mfa.totp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.backend.auth.mfa.otp.Totp;

@Configuration(proxyBeanMethods = false)
class TotpConfig {

    /** HMAC-SHA1, 6 digits, 30-second steps: what every authenticator app understands. */
    @Bean
    Totp totp() {
        return Totp.authenticatorAppDefaults();
    }
}
