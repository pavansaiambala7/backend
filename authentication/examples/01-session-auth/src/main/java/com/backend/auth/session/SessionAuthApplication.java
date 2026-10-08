package com.backend.auth.session;

import java.time.Clock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SessionAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(SessionAuthApplication.class, args);
    }

    /** Injected wherever time matters (throttling, absolute timeout) so tests can control it. */
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
