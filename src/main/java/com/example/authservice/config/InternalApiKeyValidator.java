package com.example.authservice.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class InternalApiKeyValidator implements ApplicationRunner {

    private static final int MIN_KEY_LENGTH = 32;

    private final InternalApiProperties internalApiProperties;

    public InternalApiKeyValidator(InternalApiProperties internalApiProperties) {
        this.internalApiProperties = internalApiProperties;
    }

    @Override
    public void run(ApplicationArguments args) {
        String key = internalApiProperties.apiKey();
        if (key == null || key.isBlank() || key.length() < MIN_KEY_LENGTH) {
            throw new IllegalStateException(
                    "INTERNAL_API_KEY must be set and at least " + MIN_KEY_LENGTH + " characters long");
        }
    }
}
