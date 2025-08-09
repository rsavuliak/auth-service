package com.example.authservice.config;

import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private final String secret;

    public JwtProperties(String secret) {
        this.secret = secret;
    }

}