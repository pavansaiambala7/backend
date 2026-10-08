package com.backend.auth.mfa;

import java.time.Clock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@ConfigurationPropertiesScan
public class MfaTotpApplication {

    public static void main(String[] args) {
        SpringApplication.run(MfaTotpApplication.class, args);
    }

    /** One clock for TOTP time steps, throttling and factor ages, so tests can move time instead of sleeping. */
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
