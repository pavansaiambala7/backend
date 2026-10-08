package com.backend.auth.apikeys;

import java.time.Clock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@ConfigurationPropertiesScan
public class ApiKeysApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiKeysApplication.class, args);
    }

    /** One clock for key expiry, last-used tracking and webhook timestamps; tests swap it to travel in time. */
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
