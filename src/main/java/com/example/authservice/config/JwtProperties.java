package com.example.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private final String secret;

    public JwtProperties(String secret) {
        this.secret = secret;
    }

    public String getSecret() {
        return secret;
    }
}